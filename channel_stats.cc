/*
  channel_stats.cc
  channel_stats plugin for Apache Traffic Server 3.0.0+

  Created by Conan Wang <buaawkl@gmail.com> on 2012-11-05.
*/

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <ts/ts.h>
#include <ts/experimental.h>

#include "debug_macros.h"

#define PLUGIN_NAME     "channel_stats"
#define PLUGIN_VERSION  "0.1"

static TSTextLogObject log;

typedef struct {
  char * host;
} cdata;

int64_t global_req_count = 0;  // 2XX requests count

static int handle_hook(TSCont contp, TSEvent event, void *edata);

static void
destroy_cdata(cdata * cd)
{
  if (cd) {
    TSfree(cd->host);
    TSfree(cd);
  }
}

static void
handle_read_req(TSCont contp, TSHttpTxn txnp)
{
  TSMBuffer bufp;
  TSMLoc hdr_loc;
  cdata * cd;

  if (TSHttpTxnClientReqGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    error("couldn't retrieve client's request");
    return;
  }

  // int length;
  // char *url = TSHttpTxnEffectiveUrlStringGet(txnp, &length);
  // debug("%*s", length, url);
  // TSfree(url);

  TSMLoc host_field_loc;
  const char* host_field;
  int host_field_length = 0;
  host_field_loc = TSMimeHdrFieldFind(bufp, hdr_loc, 
                                      TS_MIME_FIELD_HOST, TS_MIME_LEN_HOST);
  if (host_field_loc) {
    host_field = TSMimeHdrFieldValueStringGet(bufp, hdr_loc, host_field_loc, 
                                              0, &host_field_length);
  } else {
    warning("no valid host header");
    TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
    return;
  }
  debug("origin host: %.*s", host_field_length, host_field);

  TSCont txn_contp = TSContCreate(handle_hook, NULL); // we reuse global hander
  cd = (cdata *) TSmalloc(sizeof(cdata));
  cd->host = TSstrndup(host_field, host_field_length);
  TSContDataSet(txn_contp, cd);

  TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, txn_contp);

  TSHandleMLocRelease(bufp, hdr_loc, host_field_loc);
  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
}

static void
handle_txn_close(TSCont contp, TSHttpTxn txnp)
{
  TSMBuffer bufp;
  TSMLoc hdr_loc;
  cdata * cd = (cdata *) TSContDataGet(contp);
  int64_t user_speed;

  if (TSHttpTxnClientRespGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    error("couldn't retrieve final response");
    return;
  }

  TSHttpStatus status = TSHttpHdrStatusGet(bufp, hdr_loc);
  if (status != TS_HTTP_STATUS_OK && status != TS_HTTP_STATUS_PARTIAL_CONTENT) {
    debug("only count 200/206 response");
    TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
    return;
  }

  int64_t body_bytes = TSHttpTxnClientRespBodyBytesGet(txnp);
  TSHRTime start_time = 0;
  TSHRTime end_time = 0;
  TSHRTime interval_time = 0;
  TSHttpTxnStartTimeGet(txnp, &start_time);
  TSHttpTxnEndTimeGet(txnp, &end_time);
  if ((start_time != 0 && end_time != 0) || end_time < start_time) {
    interval_time = end_time - start_time;
  } else {
    error("not valid time, start: %"PRId64", end: %"PRId64"", start_time, end_time);
    goto done;
  }
  user_speed = (interval_time == 0) ? body_bytes : (int)((float)body_bytes / interval_time * TS_HRTIME_SECOND);

  // global_req_count += 1;
  __sync_fetch_and_add(&global_req_count, 1);

  debug("origin host in ContData: %s", cd->host);
  debug("body bytes: %"PRId64"", body_bytes);
  debug("start time: %"PRId64"", start_time);
  debug("end time: %"PRId64"", end_time);
  debug("interval time: %"PRId64"", interval_time);
  debug("interval seconds: %.5f", interval_time / (float)TS_HRTIME_SECOND);
  debug("speed bytes per second: %lld", user_speed);
  debug("2xx req count: %"PRId64"", global_req_count);

done:
  TSHandleMLocRelease(bufp, TS_NULL_MLOC, hdr_loc);
}

static int
handle_hook(TSCont contp, TSEvent event, void *edata) {
  TSHttpTxn txnp = (TSHttpTxn) edata;

  switch (event) {
    case TS_EVENT_HTTP_READ_REQUEST_HDR: // for global contp
      debug("---------- new request ----------");
      handle_read_req(contp, txnp);
      break;
    case TS_EVENT_HTTP_TXN_CLOSE: // for txn contp
      handle_txn_close(contp, txnp);
      destroy_cdata((cdata *) TSContDataGet(contp));
      TSContDestroy(contp);
      break;
    default:
      error("unknown event for this plugin");
      // TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
      // return 0;
  }

  TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);

  return 0;
}

static int
check_ts_version()
{
  const char *ts_version = TSTrafficServerVersionGet();
  int result = 0;

  if (ts_version) {
    int major_ts_version = 0; 
    int minor_ts_version = 0;
    int patch_ts_version = 0;

    if (sscanf(ts_version, "%d.%d.%d", &major_ts_version, &minor_ts_version,
                &patch_ts_version) != 3) {
      return 0;
    }

    /* Need at least TS 3.0.0 */
    if (major_ts_version >= 3) {
      result = 1;
    }
  }

  return result;
}

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name = (char *)PLUGIN_NAME;
  info.vendor_name = (char *)"sinaedge_wkl";
  info.support_email = (char *)"buaawkl@gmail.com";

  if (TSPluginRegister(TS_SDK_VERSION_3_0, &info) != TS_SUCCESS) {
    error("plugin's global part registration failed.");
    return;
  }

  if (!check_ts_version()) {
    error("plugin's global part requires Traffic Server 3.0.0 or later");
    return;
  }

  if (!log) {
    TSTextLogObjectCreate(PLUGIN_NAME, TS_LOG_MODE_ADD_TIMESTAMP, &log);
  }

  if (log) {
    TSTextLogObjectWrite(log, (char *)"%s plugin starting... version: %s",
                         PLUGIN_NAME, PLUGIN_VERSION);
  }
  debug("%s plugin starting... version: %s", PLUGIN_NAME, PLUGIN_VERSION);

  // TSCont cont = TSContCreate(handle_hook, TSMutexCreate());  we do not have global contp data
  TSCont cont = TSContCreate(handle_hook, NULL);
  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, cont);
}
