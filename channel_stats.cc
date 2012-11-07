/*
  channel_stats.cc
  channel_stats plugin for Apache Traffic Server 3.0.0+

  This plugin collect the runtime statstics (speed, request count and more in
  the future) for each channel. The stats is exposed with http interface.
  (the code of interface is from 'stats_over_http' plugin)

  Created by Conan Wang <buaawkl@gmail.com> on 2012-11-05.
*/

#include <string.h>
#include <stdio.h>
#include <ctype.h>
#include <inttypes.h>
#include <string>
// #include <ext/hash_map>
#include <map>
#define __STDC_FORMAT_MACROS

#include <ts/ts.h>
#include <ts/experimental.h>

#include "debug_macros.h"

#define PLUGIN_NAME     "channel_stats"
#define PLUGIN_VERSION  "0.1"

static std::string api_path = "_cstats";
static TSTextLogObject log;

struct cdata {
  // const char * method; TODO only count GET
  char * host;
};

// global stats
uint64_t global_response_count_2xx_get = 0;  // 2XX GET response count

// channel stats
struct channel_stat {
  channel_stat()
      : response_bytes_content(0), 
        response_count_2xx(0),
        speed_bytes_per_sec_50k(0) {
  }

  inline void increment(uint64_t rbc, uint64_t rc2, uint64_t sbps5) {
    __sync_fetch_and_add(&response_bytes_content, rbc);
    if (rc2 == 1) __sync_fetch_and_add(&response_count_2xx, rc2);
    if (sbps5 == 1) __sync_fetch_and_add(&speed_bytes_per_sec_50k, sbps5);
  }

  void debug_channel() {
    debug("response.bytes.content: %" PRIu64 "", response_bytes_content);
    debug("response.count.2xx: %" PRIu64 "", response_count_2xx);
    debug("speed.bytes_per_sec_50k: %" PRIu64 "", speed_bytes_per_sec_50k);
  }

  uint64_t response_bytes_content;
  uint64_t response_count_2xx;
  uint64_t speed_bytes_per_sec_50k;
};

// using namespace __gnu_cxx;
// typedef __gnu_cxx::hash_map<std::string, channel_stat> stats_map_type;
typedef std::map<std::string, channel_stat *> stats_map_type;
typedef stats_map_type::const_iterator const_iterator;
typedef stats_map_type::iterator iterator;

static stats_map_type channel_stats;

static int handle_hook(TSCont contp, TSEvent event, void *edata);
static int api_origin(TSCont contp, TSEvent event, void *edata);

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
  std::string host = std::string(cd->host);
  uint64_t user_speed;
  uint64_t body_bytes;
  TSHRTime start_time = 0;
  TSHRTime end_time = 0;
  TSHRTime interval_time = 0;
  iterator stat_it;
  channel_stat *stat;

  if (TSHttpTxnClientRespGet(txnp, &bufp, &hdr_loc) != TS_SUCCESS) {
    error("couldn't retrieve final response");
    return;
  }

  TSHttpStatus status = TSHttpHdrStatusGet(bufp, hdr_loc);
  if (status != TS_HTTP_STATUS_OK && status != TS_HTTP_STATUS_PARTIAL_CONTENT) {
    debug("only count 200/206 response");
    goto cleanup;
  }

  body_bytes = TSHttpTxnClientRespBodyBytesGet(txnp);
  TSHttpTxnStartTimeGet(txnp, &start_time);
  TSHttpTxnEndTimeGet(txnp, &end_time);
  if ((start_time != 0 && end_time != 0) || end_time < start_time) {
    interval_time = end_time - start_time;
  } else {
    error("not valid time, start: %"PRId64", end: %"PRId64"", start_time, end_time);
    goto cleanup;
  }
  // TODO body_bytes may = 0, set it inf?
  user_speed = (interval_time == 0) ? body_bytes : (int)((float)body_bytes / interval_time * TS_HRTIME_SECOND);

  __sync_fetch_and_add(&global_response_count_2xx_get, 1);

  debug("origin host in ContData: %s", host.c_str());
  debug("body bytes: %" PRIu64 "", body_bytes);
  debug("start time: %" PRId64 "", start_time);
  debug("end time: %" PRId64 "", end_time);
  debug("interval time: %" PRId64 "", interval_time);
  debug("interval seconds: %.5f", interval_time / (float)TS_HRTIME_SECOND);
  debug("speed bytes per second: %" PRIu64 "", user_speed);
  debug("2xx req count: %" PRIu64 "", global_response_count_2xx_get);

  stat_it = channel_stats.find(host);
  if (stat_it == channel_stats.end()) {
    stat = new channel_stat();
    channel_stats.insert(std::make_pair(host, stat));
    // check if insert success, may insert concurrently, if not, delete stat
    debug("*********** new channel ***********")
    stat->increment(body_bytes, 1, user_speed < 500000 ? 1 : 0);
    stat->debug_channel();
  } else {
    stat_it->second->increment(body_bytes, 1, user_speed < 500000 ? 1 : 0);
    stat_it->second->debug_channel();
  }

cleanup:
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


// below is api part

typedef struct stats_state_t
{
  TSVConn net_vc;
  TSVIO read_vio;
  TSVIO write_vio;

  TSIOBuffer req_buffer;
  TSIOBuffer resp_buffer;
  TSIOBufferReader resp_reader;

  int output_bytes;
  int body_written;
} stats_state;

static void
stats_cleanup(TSCont contp, stats_state * my_state)
{
  if (my_state->req_buffer) {
    TSIOBufferDestroy(my_state->req_buffer);
    my_state->req_buffer = NULL;
  }

  if (my_state->resp_buffer) {
    TSIOBufferDestroy(my_state->resp_buffer);
    my_state->resp_buffer = NULL;
  }
  TSVConnClose(my_state->net_vc);
  TSfree(my_state);
  TSContDestroy(contp);
}

static void
stats_process_accept(TSCont contp, stats_state * my_state)
{

  my_state->req_buffer = TSIOBufferCreate();
  my_state->resp_buffer = TSIOBufferCreate();
  my_state->resp_reader = TSIOBufferReaderAlloc(my_state->resp_buffer);
  my_state->read_vio = TSVConnRead(my_state->net_vc, contp, my_state->req_buffer, INT64_MAX);
}

static int
stats_add_data_to_resp_buffer(const char *s, stats_state * my_state)
{
  int s_len = strlen(s);

  TSIOBufferWrite(my_state->resp_buffer, s, s_len);

  return s_len;
}

static const char RESP_HEADER[] =
  "HTTP/1.0 200 Ok\r\nContent-Type: application/json\r\nCache-Control: no-cache\r\n\r\n";

static int
stats_add_resp_header(stats_state * my_state)
{
  return stats_add_data_to_resp_buffer(RESP_HEADER, my_state);
}

static void
stats_process_read(TSCont contp, TSEvent event, stats_state * my_state)
{
  debug_api("stats_process_read(%d)", event);
  if (event == TS_EVENT_VCONN_READ_READY) {
    my_state->output_bytes = stats_add_resp_header(my_state);
    TSVConnShutdown(my_state->net_vc, 1, 0);
    my_state->write_vio = TSVConnWrite(my_state->net_vc, contp, my_state->resp_reader, INT64_MAX);
  } else if (event == TS_EVENT_ERROR) {
    error_api("stats_process_read: Received TS_EVENT_ERROR\n");
  } else if (event == TS_EVENT_VCONN_EOS) {
    /* client may end the connection, simply return */
    return;
  } else if (event == TS_EVENT_NET_ACCEPT_FAILED) {
    error_api("stats_process_read: Received TS_EVENT_NET_ACCEPT_FAILED\n");
  } else {
    error_api("Unexpected Event %d\n", event);
    // TSReleaseAssert(!"Unexpected Event");
  }
}

#define APPEND(a) my_state->output_bytes += stats_add_data_to_resp_buffer(a, my_state)
#define APPEND_STAT(a, fmt, v) do { \
  char b[256]; \
  if(snprintf(b, sizeof(b), "\"%s\": \"" fmt "\",\n", a, v) < (signed)sizeof(b)) \
    APPEND(b); \
} while(0)


static void
json_out_stat(TSRecordType rec_type, void *edata, int registered,
              const char *name, TSRecordDataType data_type,
              TSRecordData *datum) {
  stats_state *my_state = (stats_state *) edata;

  switch(data_type) {
  case TS_RECORDDATATYPE_COUNTER:
    APPEND_STAT(name, "%" PRId64, datum->rec_counter); break;
  case TS_RECORDDATATYPE_INT:
    APPEND_STAT(name, "%" PRIu64, datum->rec_int); break;
  case TS_RECORDDATATYPE_FLOAT:
    APPEND_STAT(name, "%f", datum->rec_float); break;
  case TS_RECORDDATATYPE_STRING:
    APPEND_STAT(name, "%s", datum->rec_string); break;
  default:
    debug_api("unkown type for %s: %d", name, data_type);
    break;
  }
}


static void
json_out_stats(stats_state * my_state)
{
  const char *version;
  APPEND("{ \"global\": {\n");

  TSRecordDump(TS_RECORDTYPE_PROCESS, json_out_stat, my_state);
  version = TSTrafficServerVersionGet();
  APPEND_STAT("response.count.2xx.get", "%" PRIu64, global_response_count_2xx_get);
  APPEND("\"server\": \"");
  APPEND(version);
  APPEND("\"\n");
  APPEND("  }\n}\n");
}

static void
stats_process_write(TSCont contp, TSEvent event, stats_state * my_state)
{
  if (event == TS_EVENT_VCONN_WRITE_READY) {
    if (my_state->body_written == 0) {
      debug_api("plugin adding response body");
      my_state->body_written = 1;
      json_out_stats(my_state);
      TSVIONBytesSet(my_state->write_vio, my_state->output_bytes);
    }
    TSVIOReenable(my_state->write_vio);
  } else if (TS_EVENT_VCONN_WRITE_COMPLETE) {
    stats_cleanup(contp, my_state);
  } else if (event == TS_EVENT_ERROR) {
    error_api("stats_process_write: Received TS_EVENT_ERROR\n");
  } else {
    error_api("Unexpected Event %d\n", event);
    // TSReleaseAssert(!"Unexpected Event");
  }
}

static int
stats_dostuff(TSCont contp, TSEvent event, void *edata)
{
  stats_state *my_state = (stats_state *) TSContDataGet(contp);
  if (event == TS_EVENT_NET_ACCEPT) {
    my_state->net_vc = (TSVConn) edata;
    stats_process_accept(contp, my_state);
  } else if (edata == my_state->read_vio) {
    stats_process_read(contp, event, my_state);
  } else if (edata == my_state->write_vio) {
    stats_process_write(contp, event, my_state);
  } else {
    error_api("Unexpected Event %d\n", event);
    // TSReleaseAssert(!"Unexpected Event");
  }
  return 0;
}

// put together with 'handle_hook'
static int
api_origin(TSCont contp, TSEvent event, void *edata)
{
  TSCont icontp;
  stats_state *my_state;
  TSHttpTxn txnp = (TSHttpTxn) edata;
  TSMBuffer reqp;
  TSMLoc hdr_loc = NULL, url_loc = NULL;
  TSEvent reenable = TS_EVENT_HTTP_CONTINUE;
  const char* path;
  int path_len = 0;

  debug_api("in the read stuff");
 
  if (TSHttpTxnClientReqGet(txnp, &reqp, &hdr_loc) != TS_SUCCESS)
    goto cleanup;
  
  if (TSHttpHdrUrlGet(reqp, hdr_loc, &url_loc) != TS_SUCCESS)
    goto cleanup;
  
  path = TSUrlPathGet(reqp, url_loc, &path_len);

  if (path_len == 0 || (unsigned)path_len != api_path.length() ||
        strncmp(api_path.c_str(), path, path_len) != 0) {
    goto notforme;
  }
  
  TSSkipRemappingSet(txnp,1); //not strictly necessary, but speed is everything these days

  /* This is us -- register our intercept */
  debug_api("Intercepting request");

  icontp = TSContCreate(stats_dostuff, TSMutexCreate());
  my_state = (stats_state *) TSmalloc(sizeof(*my_state));
  memset(my_state, 0, sizeof(*my_state));
  TSContDataSet(icontp, my_state);
  TSHttpTxnIntercept(icontp, txnp);
  goto cleanup;

 notforme:

 cleanup:
  if(url_loc) TSHandleMLocRelease(reqp, hdr_loc, url_loc);
  if(hdr_loc) TSHandleMLocRelease(reqp, TS_NULL_MLOC, hdr_loc);

  TSHttpTxnReenable(txnp, reenable);
  return 0;
}

// initial part

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
  if (argc > 2) {
    fatal("plugin does not accept more than 1 argument");
  } else if (argc == 2) {
    api_path = std::string(argv[1]);
    debug_api("stats api path: %s", api_path.c_str());
  }

  TSPluginRegistrationInfo info;

  info.plugin_name = (char *)PLUGIN_NAME;
  info.vendor_name = (char *)"wkl";
  info.support_email = (char *)"buaawkl@gmail.com";

  if (TSPluginRegister(TS_SDK_VERSION_3_0, &info) != TS_SUCCESS) {
    fatal("plugin registration failed.");
    return;
  }

  if (!check_ts_version()) {
    fatal("plugin requires Traffic Server 3.0.0 or later");
    return;
  }

  if (!log) {
    TSTextLogObjectCreate(PLUGIN_NAME, TS_LOG_MODE_ADD_TIMESTAMP, &log);
  }

  if (log) {
    TSTextLogObjectWrite(log, (char *)"%s(%s) plugin starting...",
                         PLUGIN_NAME, PLUGIN_VERSION);
  }
  debug("%s(%s) plugin starting...", PLUGIN_NAME, PLUGIN_VERSION);

  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, TSContCreate(api_origin, NULL));
  debug_api("stats api module registered");

  // TSCont cont = TSContCreate(handle_hook, TSMutexCreate());  we do not have global contp data
  TSCont cont = TSContCreate(handle_hook, NULL);
  TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, cont);
}

