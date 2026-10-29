# zendure.be - Zendure SolarFlow 2400 AC executor for a Tasmota Zigbee/Ethernet gateway
#
# Spec reference: "Pilotage batterie Zendure depuis AWS via passerelle Tasmota" (2026-09-23)
# This gateway is a SAFE EXECUTOR, not a controller: the control law lives in the cloud
# backend. Only three things are enforced locally, unconditionally (spec §1 "ce qui reste
# local"): setpoint expiry (deadman), the daily flash-write cap on acMode, and export/
# injection detection with fallback to a safe state. Discharge is also cut when the ZLinky
# goes silent, since export detection is blind without it.
#
# CONFIRM-ON-FIRST-DEPLOY: the exact JSON key names for live SoC/temperature/power inside
# `properties`/`packData` were not given by the spec (only the write-side limit properties
# were verified: acMode, inputLimit, outputLimit, smartMode, minSoc, socSet, gridReverse,
# inverseMaxPower, chargeMaxLimit). Run `ZenDebug 1` once after commissioning: it dumps the
# raw /properties/report body to the console so the candidate keys below (ZEN_KEY_*) can be
# corrected if the live device uses different names. Do not trust them as verified.

import string
import json
import persist
import mqtt

# --- Fixed, verified device parameters (spec §2, §4.1) ---------------------------------
var ZEN_IP_DEFAULT  = "192.168.1.69"   # factory default - overridable at runtime, see zen_ip below
var ZEN_TOPIC_DEFAULT = "tasmota_C76FE4"   # this gateway's own Tasmota %topic% - overridable, see zen_topic below
var ZEN_SN          = "HOA1NAN9N385378"
var ZEN_PATH_REPORT = "/properties/report"
var ZEN_PATH_WRITE  = "/properties/write"
var ZEN_MAX_BODY    = 512          # local API receive cap (spec §4.1)
var ZEN_HTTP_TIMEOUT_MS = 2000     # spec §7 Berry pitfalls: keep it short, webclient blocks the Zigbee coordinator

# Best-effort candidate keys for live telemetry - see CONFIRM-ON-FIRST-DEPLOY above
var ZEN_KEY_SOC     = "electricLevel"
var ZEN_KEY_TEMP    = "hyperTmp"       # tenths of Kelvin per spec §7 (3091 -> 36.0C)

# --- Non-negotiable local safety constants (spec §4.3, §4.5) ---------------------------
var ZEN_MIN_WRITE_INTERVAL_MS = 5000
var ZEN_ACMODE_DAILY_CAP_DEFAULT = 10
var ZEN_TTL_DEFAULT_S = 300
var ZEN_TTL_MAX_S     = 3600
var ZEN_WATCHDOG_MS   = 3600 * 1000   # 1h, spec §4.4 zen_watchdog
var ZEN_POLL_PERIOD_MS = 30 * 1000
var ZEN_INJECTION_WINDOW_MS = 10 * 60 * 1000   # spec §4.5bis
var ZEN_MISMATCH_LIMIT = 3            # spec §4.6
var ZEN_METER_STALE_MS = 60 * 1000    # ZLinky is polled every 10s - 60s of silence means the meter is gone

# --- Runtime state (module-level `var` - must be declared before functions that use them,
#     spec §7 Berry pitfall: file-scope var capture happens at compile time) -------------
var zen_ip           = ZEN_IP_DEFAULT   # runtime-changeable via `ZenConfig {"ip":"..."}`, persisted
var zen_topic         = ZEN_TOPIC_DEFAULT   # runtime-changeable via `ZenConfig {"topic":"..."}`, persisted
var zen_charge_max   = 2400   # re-read from report, spec §4.5c "jamais codees en dur"
var zen_output_max   = 800
var zen_last_write_ms = 0
var zen_pending_props = nil   # queued write waiting out the 5s rate limit
var zen_pending_cb    = nil
var zen_write_timer_armed = false

var zen_plan = nil            # {seq, ttl_s, mode, watts, min_soc, local_loop, deadline_ms, expired}
var zen_last_applied_seq = 0
var zen_effective = {"acMode": 0, "inputLimit": 0, "outputLimit": 0}  # last known-applied setpoint
var zen_last_plan_ms = 0      # for zen_watchdog (last time ANY valid plan was received)

var zen_acmode_count = 0
var zen_acmode_window_start_ms = 0   # rolling 24h window, millis()-based (spec: never wall-clock for safety logic)

var zen_mismatch_count = 0
var zen_suspended = false

var zen_last_papp = nil
var zen_last_papp_ms = 0      # when zen_last_papp was received - 0 means never since boot
var zen_meter_stale = false   # latched so ZENDURE_METER_STALE/OK publish once per transition
var zen_index_history = []    # [[ms, wh_value], ...] for injection detection
var zen_export_suspected = false

var zen_local_loop_enabled = false   # spec §4.5bis: dormant unless ZenPlan sets local_loop:1
var zen_local_loop_setpoint = 0

var zen_debug = false
var zen_started_ms = 0

# Pre-declare all top-level functions as globals so they can call each other regardless of
# textual order (spec §7 Berry pitfall: file-scope name capture happens at compile time -
# this applies to functions calling each other, not just plain `var` state).
var zen_clampi, zen_hex_to_wh, zen_now, zen_acmode_window_check, zen_acmode_cap, zen_pub
var zen_get, zen_post, zen_flush_pending, zen_apply_write
var zen_refresh_bounds, zen_clamp_for_mode
var zen_fallback_state, zen_check_ttl, zen_watchdog
var zen_local_loop, zen_on_papp, zen_on_zlinky_full, zen_meter_fresh, zen_check_meter
var zen_check_effect, zen_poll, zen_poll_tick
var zen_publish_ack, zen_cmd_plan, zen_cmd_write, zen_cmd_state, zen_cmd_debug, zen_cmd_config, zen_valid_ip
var zen_hello

# =========================================================================================
# Helpers
# =========================================================================================

zen_clampi = def(v, lo, hi)
  if v < lo return lo end
  if v > hi return hi end
  return v
end

# Explicit topic, NOT tasmota.publish_result(): that helper collapses every RESULT_OR_TELE/
# RESULT_OR_STAT publish down to a plain ".../RESULT" topic unless the device has SetOption4
# enabled - which most installs (including this one) don't, and which we won't require just
# for this driver since it'd change behavior for every other native publish on the device too.
zen_pub = def(subtopic, payload_map)
  mqtt.publish("tele/" + zen_topic + "/" + subtopic, json.dump(payload_map))
end

zen_hex_to_wh = def(s)
  if s == nil return nil end
  if type(s) == 'int' return s end
  if string.find(s, "0x") != 0 && string.find(s, "0X") != 0
    s = "0x" + s
  end
  try
    return int(s)
  except .. as e, m
    return nil
  end
end

zen_now = def()
  return tasmota.millis()
end

# Rolling day counter for the acMode write cap - millis()-based on purpose (spec: local
# safety logic must never depend on wall-clock/NTP).
zen_acmode_window_check = def()
  var now = zen_now()
  if zen_acmode_window_start_ms == 0 || (now - zen_acmode_window_start_ms) >= 86400000
    zen_acmode_window_start_ms = now
    zen_acmode_count = 0
    persist.zen_acmode_count = 0
    persist.zen_acmode_window_start_ms = now
    persist.save()
  end
end

zen_acmode_cap = def()
  if persist.has("zen_acmode_cap")
    return persist.zen_acmode_cap
  end
  return ZEN_ACMODE_DAILY_CAP_DEFAULT
end

# =========================================================================================
# §4.4 zen_get / zen_post
# =========================================================================================

zen_get = def(path)
  if zen_now() - zen_started_ms < 5000
    return nil   # spec §7 pitfall: webclient can crash before network/heap is ready
  end
  var cl = webclient()
  cl.set_timeouts(ZEN_HTTP_TIMEOUT_MS, ZEN_HTTP_TIMEOUT_MS)
  var ok = cl.begin("http://" + zen_ip + path)
  if !ok
    cl.close()
    return nil
  end
  var code = cl.GET()
  if code != 200
    cl.close()
    return nil
  end
  var body = cl.get_string()   # get_string() already closes the connection
  return body
end

# Injects smartMode:1 and sn on EVERY write - the caller's map is never trusted as-is
# (spec §4.3 rule 1: "La fonction d'ecriture doit l'injecter elle-meme").
zen_post = def(properties_map)
  if zen_now() - zen_started_ms < 5000
    return false
  end
  var props = {}
  for k: properties_map.keys()
    props[k] = properties_map[k]
  end
  props["smartMode"] = 1

  var body = {"sn": ZEN_SN, "properties": props}
  var payload = json.dump(body)
  if size(payload) > ZEN_MAX_BODY
    tasmota.log(f"ZEN: write body too large ({size(payload)}B > {ZEN_MAX_BODY}B), aborted", 2)
    return false
  end

  var cl = webclient()
  cl.set_timeouts(ZEN_HTTP_TIMEOUT_MS, ZEN_HTTP_TIMEOUT_MS)
  var ok = cl.begin("http://" + zen_ip + ZEN_PATH_WRITE)
  if !ok
    cl.close()
    return false
  end
  cl.addheader("Content-Type", "application/json")
  var code = cl.POST(payload)
  cl.close()
  # spec §4.6: a 200/{"success":true} proves nothing by itself - only the follow-up
  # report comparison (zen_poll / zen_check_effect) can confirm the write actually stuck.
  return (code == 200)
end

# =========================================================================================
# Rate-limited, gated write path - every setpoint change in the driver goes through this.
# =========================================================================================

zen_flush_pending = def()
  zen_write_timer_armed = false
  if zen_pending_props == nil return end
  var props = zen_pending_props
  var cb = zen_pending_cb
  zen_pending_props = nil
  zen_pending_cb = nil
  zen_apply_write(props, cb)
end

zen_apply_write = def(props, cb)
  if zen_suspended
    if cb != nil cb(false, "suspended") end
    return
  end
  var now = zen_now()
  var elapsed = now - zen_last_write_ms
  if zen_last_write_ms != 0 && elapsed < ZEN_MIN_WRITE_INTERVAL_MS
    # spec §4.3 rule 4: 5s minimum between writes - queue the LATEST request only,
    # never a burst, so a misbehaving backend can't wear the battery's flash.
    zen_pending_props = props
    zen_pending_cb = cb
    if !zen_write_timer_armed
      zen_write_timer_armed = true
      tasmota.set_timer(ZEN_MIN_WRITE_INTERVAL_MS - elapsed + 20, zen_flush_pending)
    end
    return
  end

  var ok = zen_post(props)
  zen_last_write_ms = zen_now()
  if ok
    if props.find("acMode") != nil
      zen_effective["acMode"] = props["acMode"]
    end
    if props.find("inputLimit") != nil
      zen_effective["inputLimit"] = props["inputLimit"]
    end
    if props.find("outputLimit") != nil
      zen_effective["outputLimit"] = props["outputLimit"]
    end
  end
  if cb != nil cb(ok, ok ? "ok" : "http_error") end
end

# =========================================================================================
# §4.5c bounds, read from the report, never hardcoded
# =========================================================================================

zen_refresh_bounds = def(report)
  var p = report.find("properties")
  if p == nil return end
  if p.find("chargeMaxLimit") != nil zen_charge_max = p["chargeMaxLimit"] end
  if p.find("inverseMaxPower") != nil zen_output_max = p["inverseMaxPower"] end
end

zen_clamp_for_mode = def(mode, watts)
  var clamped = false
  var lo = 0
  var hi = (mode == "charge") ? zen_charge_max : zen_output_max
  var w = watts
  if w == nil w = 0 end
  if w < lo w = lo clamped = true end
  if w > hi w = hi clamped = true end
  return [w, clamped]
end

# =========================================================================================
# §4.5a Deadman / TTL, §4.4 zen_watchdog
# =========================================================================================

zen_fallback_state = def(reason)
  # "acMode inchange, inputLimit = 0, outputLimit = 0" (spec §4.5a)
  zen_apply_write({"inputLimit": 0, "outputLimit": 0}, def(ok, why)
    if !ok tasmota.log("ZEN: fallback write failed: " + why, 2) end
  end)
  zen_local_loop_enabled = false
  zen_pub("ZENDURE_PLAN_EXPIRED", {"reason": reason, "seq": zen_last_applied_seq})
end

zen_check_ttl = def()
  if zen_plan == nil || zen_plan["expired"] return end
  if zen_now() >= zen_plan["deadline_ms"]
    zen_plan["expired"] = true
    zen_fallback_state("ttl_expired")
  end
end

zen_watchdog = def()
  if zen_last_plan_ms == 0
    # No plan since boot: whatever the battery is doing was set before the reboot and its TTL
    # is unknown - treat it as expired after one default TTL instead of letting it run forever.
    if (zen_now() - zen_started_ms) >= ZEN_TTL_DEFAULT_S * 1000
      zen_fallback_state("no_plan_since_boot")
      zen_last_plan_ms = zen_now()   # hand over to the regular 1h silence watchdog
    end
    return
  end
  if (zen_now() - zen_last_plan_ms) >= ZEN_WATCHDOG_MS
    zen_fallback_state("watchdog_1h_silence")
    zen_last_plan_ms = zen_now()   # avoid re-firing every second while the outage continues
  end
end

# =========================================================================================
# §4.5bis local loop - dormant unless explicitly enabled by a ZenPlan.local_loop:1
# =========================================================================================
var ZEN_LOCAL_TARGET_W  = 200
var ZEN_LOCAL_DEADBAND  = 80
var ZEN_LOCAL_MAX_OUT   = 800

zen_local_loop = def(papp)
  if !zen_local_loop_enabled return end
  if papp == nil return end
  var error = papp - ZEN_LOCAL_TARGET_W
  if (error < 0 ? -error : error) < ZEN_LOCAL_DEADBAND return end
  var sp = zen_clampi(zen_local_loop_setpoint + error, 0, ZEN_LOCAL_MAX_OUT)
  zen_local_loop_setpoint = sp
  var r = zen_clamp_for_mode("discharge", sp)
  zen_apply_write({"acMode": 2, "outputLimit": r[0]}, nil)
end

zen_on_papp = def(value, trigger, msg)
  zen_last_papp = value
  zen_last_papp_ms = zen_now()
  if zen_local_loop_enabled
    zen_local_loop(value)
  end
end

# =========================================================================================
# Meter freshness - the export detector below only runs when ZLinky messages arrive, so a
# silent meter (unpowered, out of range) would otherwise disable it without any signal.
# =========================================================================================

zen_meter_fresh = def()
  return zen_last_papp_ms != 0 && (zen_now() - zen_last_papp_ms) < ZEN_METER_STALE_MS
end

zen_check_meter = def()
  # Boot grace: the ZLinky rule polls every 10s, give it a full window before calling it gone.
  if zen_last_papp_ms == 0 && (zen_now() - zen_started_ms) < ZEN_METER_STALE_MS return end
  if zen_meter_fresh()
    if zen_meter_stale
      zen_meter_stale = false
      zen_pub("ZENDURE_METER_OK", {"papp": zen_last_papp})
    end
    return
  end
  var age_s = (zen_last_papp_ms == 0) ? -1 : (zen_now() - zen_last_papp_ms) / 1000
  if !zen_meter_stale
    zen_meter_stale = true
    zen_pub("ZENDURE_METER_STALE", {"age_s": age_s, "out_lim": zen_effective["outputLimit"]})
  end
  # Discharging blind can export to the grid undetected - cut it. Charging can't export,
  # so inputLimit is left alone. Re-checked every second, so a discharge plan received
  # while the meter is still silent gets cut as well.
  if zen_effective["outputLimit"] > 0
    zen_apply_write({"outputLimit": 0}, def(ok, why)
      if !ok tasmota.log("ZEN: meter-stale fallback write failed: " + why, 2) end
    end)
  end
end

# =========================================================================================
# §4.5d Injection / export detector - ALWAYS active, cloud mode included
# =========================================================================================

zen_on_zlinky_full = def(value, trigger, msg)
  # msg is the full ZbReceived#ZLinky map. The Wh index (cluster 0x0702, attr 0x0000) is not
  # decoded to a friendly name by Tasmota (spec §7: no multiplier/divisor exposed) - it comes
  # back as a raw hex-string keyed by the cluster/attribute id. Match heuristically.
  if msg == nil return end
  var raw = nil
  for k: msg.keys()
    if string.find(k, "0702") >= 0
      raw = msg[k]
      break
    end
  end
  if raw == nil return end
  var wh = zen_hex_to_wh(raw)
  if wh == nil return end

  var now = zen_now()
  # Throttle to ~1 sample/min: keeps the buffer small regardless of how often 0x0702
  # actually reports, and keeps the oldest kept sample close to exactly `window` old.
  if size(zen_index_history) == 0 || (now - zen_index_history[size(zen_index_history)-1][0]) >= 60000
    zen_index_history.push([now, wh])
  end
  # Drop the oldest sample only while the NEXT one is already >= window old, so slot 0
  # always holds the tightest available "at least `window` old" reference point.
  while size(zen_index_history) > 1 && (now - zen_index_history[1][0]) >= ZEN_INJECTION_WINDOW_MS
    zen_index_history.remove(0)
  end
  if size(zen_index_history) == 0 return end
  var oldest = zen_index_history[0]
  if (now - oldest[0]) < ZEN_INJECTION_WINDOW_MS return end   # not enough history yet

  var frozen = (wh == oldest[1])
  if frozen && zen_effective["outputLimit"] > 0
    if !zen_export_suspected
      zen_export_suspected = true
      var old_limit = zen_effective["outputLimit"]   # capture before zen_apply_write mutates zen_effective
      var new_limit = int(old_limit * 0.7)
      zen_apply_write({"outputLimit": new_limit}, nil)
      zen_pub("ZENDURE_EXPORT_SUSPECTED", {"index_wh": wh, "out_lim_before": old_limit, "out_lim_after": new_limit})
    end
  else
    zen_export_suspected = false
  end
end

# =========================================================================================
# §4.6 Effect verification
# =========================================================================================

zen_check_effect = def(report)
  var p = report.find("properties")
  if p == nil return true end
  # Only meaningful once a setpoint is actually active (not mid-expiry, not brand new).
  var mismatch = false
  if p.find("outputLimit") != nil && zen_effective["outputLimit"] != p["outputLimit"]
    mismatch = true
  end
  if p.find("acMode") != nil && zen_effective["acMode"] != 0 && zen_effective["acMode"] != p["acMode"]
    mismatch = true
  end

  if mismatch
    zen_mismatch_count += 1
    if zen_mismatch_count >= ZEN_MISMATCH_LIMIT && !zen_suspended
      zen_suspended = true
      zen_pub("ZENDURE_SETPOINT_REJECTED", {"expected": zen_effective, "reported": {"acMode": p.find("acMode"), "outputLimit": p.find("outputLimit"), "inputLimit": p.find("inputLimit")}})
    end
    return false
  else
    zen_mismatch_count = 0
    return true
  end
end

# =========================================================================================
# §4.4 zen_poll - periodic read, publish, effect check, re-arm
# =========================================================================================

zen_poll = def()
  var body = zen_get(ZEN_PATH_REPORT)
  var ok_read = 1
  var report = nil
  if body != nil
    try
      report = json.load(body)
    except .. as e, m
      report = nil
    end
  end

  var ok_effect = 1
  if report != nil
    zen_refresh_bounds(report)
    if zen_debug
      tasmota.log("ZEN raw report: " + body, 3)
      zen_debug = false
    end
    var rp = report.find("properties")
    if zen_plan == nil && rp != nil
      # Nothing commanded since boot: adopt the battery's real state instead of assuming
      # zeros. Otherwise check_effect flags a bogus mismatch and suspends the driver, and the
      # export detector/meter guard (gated on outputLimit > 0) stay blind to a live discharge.
      for k: ["acMode", "inputLimit", "outputLimit"]
        if rp.find(k) != nil zen_effective[k] = rp[k] end
      end
    else
      ok_effect = zen_check_effect(report) ? 1 : 0
    end
  else
    ok_read = 0
  end

  var p = (report != nil) ? report.find("properties") : nil
  var soc = (p != nil && p.find(ZEN_KEY_SOC) != nil) ? p[ZEN_KEY_SOC] : -1
  var tmp = (p != nil && p.find(ZEN_KEY_TEMP) != nil) ? p[ZEN_KEY_TEMP] / 10.0 - 273.15 : -1
  var acmode = (p != nil && p.find("acMode") != nil) ? p["acMode"] : zen_effective["acMode"]
  var in_lim = (p != nil && p.find("inputLimit") != nil) ? p["inputLimit"] : zen_effective["inputLimit"]
  var out_lim = (p != nil && p.find("outputLimit") != nil) ? p["outputLimit"] : zen_effective["outputLimit"]

  # A silent ZLinky must read as unknown (-1), never as its last value frozen in time.
  var papp = zen_meter_fresh() ? zen_last_papp : -1
  var tele = {
    "soc": soc,
    "chg_w": (acmode == 1) ? in_lim : 0,     # setpoint echo, NOT a measurement (spec §7 outputHomePower pitfall)
    "dis_w": (acmode == 2) ? out_lim : 0,
    "grid_w": papp,
    "home_w": papp,
    "meter_age_s": (zen_last_papp_ms == 0) ? -1 : (zen_now() - zen_last_papp_ms) / 1000,
    "acmode": acmode,
    "in_lim": in_lim,
    "out_lim": out_lim,
    "tmp_dc": tmp,
    "setpoint": (zen_plan != nil && !zen_plan["expired"]) ? zen_plan["watts"] : 0,
    "loop": zen_local_loop_enabled ? 1 : 0,
    "ok": (ok_read == 1 && ok_effect == 1) ? 1 : 0
  }
  zen_pub("ZENDURE", tele)
end

# Self-rearming wrapper for the periodic chain. Kept separate from zen_poll() itself so that
# ZenState/ZenDebug can force an out-of-band read/publish without spawning a second,
# permanently-duplicated polling timer chain.
zen_poll_tick = def()
  zen_poll()
  tasmota.set_timer(ZEN_POLL_PERIOD_MS, zen_poll_tick)
end

# =========================================================================================
# §5.1 MQTT command surface
# =========================================================================================

zen_publish_ack = def(seq, applied, clamped, effective)
  zen_pub("ZENDURE_ACK", {"seq": seq, "applied": applied ? 1 : 0, "clamped": clamped ? 1 : 0, "effective": effective})
end

zen_cmd_plan = def(cmd, idx, payload, payload_json)
  var pj = payload_json
  if pj == nil
    try
      pj = json.load(payload)
    except .. as e, m
      pj = nil
    end
  end
  if pj == nil || pj.find("seq") == nil || pj.find("mode") == nil
    tasmota.resp_cmnd_error()
    return
  end

  var seq = pj["seq"]
  if seq <= zen_last_applied_seq
    zen_publish_ack(seq, false, false, zen_effective)
    tasmota.resp_cmnd_str(json.dump({"applied": 0, "reason": "seq_stale"}))
    return
  end

  var mode = pj["mode"]
  if mode != "idle" && mode != "charge" && mode != "discharge"
    zen_publish_ack(seq, false, false, zen_effective)
    tasmota.resp_cmnd_error()
    return
  end

  var ttl_s = pj.find("ttl_s")
  if ttl_s == nil ttl_s = ZEN_TTL_DEFAULT_S end
  ttl_s = zen_clampi(ttl_s, 1, ZEN_TTL_MAX_S)

  var watts = pj.find("watts")
  if watts == nil watts = 0 end

  var local_loop = pj.find("local_loop")
  local_loop = (local_loop != nil && local_loop == 1)

  var clamped = false
  var props = {}
  var want_acmode = nil

  if mode == "idle"
    props["inputLimit"] = 0
    props["outputLimit"] = 0
  elif mode == "charge"
    var r = zen_clamp_for_mode("charge", watts)
    want_acmode = 1
    props["inputLimit"] = r[0]
    clamped = r[1]
    props["outputLimit"] = 0
  elif mode == "discharge"
    var r = zen_clamp_for_mode("discharge", watts)
    want_acmode = 2
    props["outputLimit"] = r[0]
    clamped = r[1]
    props["inputLimit"] = 0
  end

  var min_soc = pj.find("min_soc")
  if min_soc != nil
    props["minSoc"] = zen_clampi(int(min_soc * 10), 0, 1000)
  end

  # spec §4.3 rule 3: acMode only changes on charge<->discharge transitions, capped daily.
  zen_acmode_window_check()
  var acmode_refused = false
  if want_acmode != nil && want_acmode != zen_effective["acMode"]
    if zen_acmode_count >= zen_acmode_cap()
      acmode_refused = true
    else
      props["acMode"] = want_acmode
      zen_acmode_count += 1
      persist.zen_acmode_count = zen_acmode_count
      persist.zen_last_applied_seq = seq
      persist.save()
    end
  end

  if acmode_refused
    zen_publish_ack(seq, false, clamped, zen_effective)
    tasmota.resp_cmnd_str(json.dump({"applied": 0, "reason": "acmode_daily_cap"}))
    return
  end

  zen_suspended = false   # a fresh, valid, in-order plan is an explicit reset signal (spec §4.6 "suspendre la boucle")
  zen_mismatch_count = 0
  zen_last_applied_seq = seq
  zen_last_plan_ms = zen_now()
  zen_local_loop_enabled = local_loop
  zen_plan = {"seq": seq, "ttl_s": ttl_s, "mode": mode, "watts": watts, "local_loop": local_loop,
              "deadline_ms": zen_now() + ttl_s * 1000, "expired": false}

  zen_apply_write(props, def(ok, why)
    zen_publish_ack(seq, ok, clamped, zen_effective)
  end)

  tasmota.resp_cmnd_done()
end

var ZEN_WRITE_WHITELIST = ["acMode", "inputLimit", "outputLimit", "minSoc", "socSet"]

zen_cmd_write = def(cmd, idx, payload, payload_json)
  var pj = payload_json
  if pj == nil
    try
      pj = json.load(payload)
    except .. as e, m
      pj = nil
    end
  end
  if pj == nil
    tasmota.resp_cmnd_error()
    return
  end
  var props = {}
  for k: pj.keys()
    var whitelisted = false
    for w: ZEN_WRITE_WHITELIST
      if w == k whitelisted = true break end
    end
    if whitelisted
      props[k] = pj[k]
    end
  end
  if size(props) == 0
    tasmota.resp_cmnd_error()
    return
  end
  # ZenWrite is a diagnostic passthrough, still rate-limited/injected via zen_apply_write -
  # never a raw WebQuery (spec §5.1: "ne jamais exposer WebQuery brut comme canal de commande").
  zen_apply_write(props, def(ok, why)
    if ok
      tasmota.resp_cmnd_done()
    else
      tasmota.resp_cmnd_str(json.dump({"applied": 0, "reason": why}))
    end
  end)
end

zen_cmd_state = def(cmd, idx, payload, payload_json)
  zen_poll()
  tasmota.resp_cmnd_done()
end

zen_cmd_debug = def(cmd, idx, payload, payload_json)
  zen_debug = true
  zen_poll()   # immediate feedback - logs the raw report right away instead of waiting up to 30s
  tasmota.resp_cmnd_done()
end

# `192.168.1.69`-shaped strings only - deliberately rejects hostnames/mDNS names (spec §1
# "Hors périmètre": no discovery in V1, a fixed address is the whole point).
zen_valid_ip = def(s)
  if s == nil || type(s) != 'string' return false end
  var parts = string.split(s, ".")
  if size(parts) != 4 return false end
  for p: parts
    if size(p) == 0 || size(p) > 3 return false end
    var n = 0
    try
      n = int(p)
    except .. as e, m
      return false
    end
    if str(n) != p return false end   # rejects "01", "1a", "-1", "1.0", etc.
    if n < 0 || n > 255 return false end
  end
  return true
end

# ZenConfig {"ip":"192.168.1.70"} - changes the battery's target address at runtime and
# persists it, so a DHCP/router change doesn't require a re-upload of this file.
# ZenConfig with no "ip" key just reports the current value.
zen_cmd_config = def(cmd, idx, payload, payload_json)
  var pj = payload_json
  if pj == nil
    try
      pj = json.load(payload)
    except .. as e, m
      pj = nil
    end
  end
  if pj != nil && pj.find("ip") != nil
    if !zen_valid_ip(pj["ip"])
      tasmota.resp_cmnd_str(json.dump({"applied": 0, "reason": "bad_ip"}))
      return
    end
    zen_ip = pj["ip"]
    persist.zen_ip = zen_ip
    persist.save()
  end
  if pj != nil && pj.find("topic") != nil
    var t = pj["topic"]
    if type(t) != 'string' || size(t) == 0
      tasmota.resp_cmnd_str(json.dump({"applied": 0, "reason": "bad_topic"}))
      return
    end
    zen_topic = t
    persist.zen_topic = zen_topic
    persist.save()
  end
  tasmota.resp_cmnd_str(json.dump({"ip": zen_ip, "topic": zen_topic}))
end

# =========================================================================================
# §4.5d Reconnection hello
# =========================================================================================

zen_hello = def(value, trigger, msg)
  var remain_ms = 0
  if zen_plan != nil && !zen_plan["expired"]
    remain_ms = zen_plan["deadline_ms"] - zen_now()
    if remain_ms < 0 remain_ms = 0 end
  end
  zen_pub("ZENDURE_HELLO", {"seq": zen_last_applied_seq, "effective": zen_effective, "ttl_remaining_ms": remain_ms, "suspended": zen_suspended ? 1 : 0})
end

# =========================================================================================
# Driver: 1s ticker for TTL/watchdog checks (spec §4.5a: relative time, not wall clock)
# =========================================================================================

class Zendure_Driver
  def init()
    zen_started_ms = tasmota.millis()

    if persist.has("zen_last_applied_seq") zen_last_applied_seq = persist.zen_last_applied_seq end
    if persist.has("zen_acmode_count") zen_acmode_count = persist.zen_acmode_count end
    if persist.has("zen_acmode_window_start_ms") zen_acmode_window_start_ms = persist.zen_acmode_window_start_ms end
    if persist.has("zen_ip") && zen_valid_ip(persist.zen_ip) zen_ip = persist.zen_ip end
    if persist.has("zen_topic") && type(persist.zen_topic) == 'string' && size(persist.zen_topic) > 0 zen_topic = persist.zen_topic end

    tasmota.add_cmd("ZenPlan", zen_cmd_plan)
    tasmota.add_cmd("ZenWrite", zen_cmd_write)
    tasmota.add_cmd("ZenState", zen_cmd_state)
    tasmota.add_cmd("ZenDebug", zen_cmd_debug)
    tasmota.add_cmd("ZenConfig", zen_cmd_config)

    tasmota.add_rule("Mqtt#Connected", zen_hello)
    tasmota.add_rule("ZbReceived#ZLinky#ApparentPower", zen_on_papp)
    tasmota.add_rule("ZbReceived#ZLinky", zen_on_zlinky_full)

    # first poll after the 5s webclient-safety delay (spec §7 pitfall)
    tasmota.set_timer(5500, zen_poll_tick)
  end

  def every_second()
    zen_check_ttl()
    zen_watchdog()
    zen_check_meter()
  end
end

zendure_driver = Zendure_Driver()
tasmota.add_driver(zendure_driver)
