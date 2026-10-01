# Mario Kart Tour (com.nintendo.zaka 4.0.0): Preservation

Prepared 2026-09-29 from local files only.

| | |
|---|---|
| Package | `com.nintendo.zaka`, "Mario Kart" (internal project name **Booster**) |
| Version | 4.0.0 (versionCode 439630101) |
| Engine | Unity **2022.3.69f1** (621633b9d04b), IL2CPP, arm64-v8a |
| Game backend | DeNA **Sakasho** SDK + Nintendo **Booster** extensions, protobuf over HTTPS to `api.mariokarttour.com` |
| Platform services | Nintendo **NPF SDK**: BaaS (`*.baas.nintendo.com`) + Nintendo Account |
| Multiplayer | Nintendo **Pia 7.2.1** P2P mesh + **Izumo** matchmaking/relay (`pvp.mariokarttour.com`, AWS us-west-2) |
| Capture | 15,431 packets, 1046.2 s (2026-09-30 02:19:48 to 02:37:14 UTC), one online race at about 736 to 880 s |

All IP addresses in this repository (including addresses embedded in host names and in packet payload dumps) are replaced with `[IP REDACTED]`. Absolute times are UTC.

---

## 0. Headline findings

1. **`global-metadata.dat` is not in the APK.** No file anywhere contains the IL2CPP magic `AF 1B B1 FA`, and `libil2cpp.so` has no `global-metadata.dat` string. The `.data` section of `libil2cpp.so` (27.8 MB) holds roughly 12 to 16 MB of high-entropy data (7.6 to 8.0 bits/byte) with no compression signature. This looks like metadata embedded in the library and encrypted by a customised loader. **Il2CppDumper could not be run statically.** See Section 4.
2. Despite that, a lot of the C# layer is still recoverable:
   * `data.unity3d` holds **3,901 MonoScript records**: class names for Assembly-CSharp (3,212), Pia, Nabe and others. That includes `SakashoIzumoManager`, `SakashoV2SecurityManager`, `NetworkManager`, `RaceMatchingP2PManager` and similar.
   * `libs2pcore.so` (Sakasho core) exports **117 `Sks*` C functions** and contains **80 REST paths** (`/v1`, `/v2`, `/v3/booster/...`) and 15 `X-Sks-*` headers.
   * `libil2cpp.so` exports about **10,400 unstripped `nn::pia` C++ symbols**, which document the multiplayer stack in detail.
3. **Game API = protobuf over HTTPS** (`application/x-protobuf`) via a native OpenSSL 3.3.1 + POCO 1.12.5 client. Auth is a session token (`X-Sks-Session-Token`) from a protobuf session-create call, plus Play Integrity nonce/JWT endpoints.
4. **NPF login is signed.** It sends an HS256 JWT whose HMAC key is an 8-digit **TOTP** (HMAC-SHA1, 600 s step) computed over `"com.nintendo.zaka:<signing-cert SHA-1>"`. That key is fully reproducible from public data (Section 6.3).
5. **None of the `*.mariokarttour.com` hostnames appear in APK plaintext.** They must live in the encrypted IL2CPP string literals, selected by `SakashoServerConfig.mEnvironment = 99` / `ResourceConfig.mSakashoEnvironment = 99`.
6. **Multiplayer (captured):** Pia NAT check (UDP 33334/34543, `NC` magic), then Izumo matchmaking over custom binary TCP to `pvp.mariokarttour.com:11401`. That points the client to an EC2 **room/relay server** (TCP + UDP on the same port, 14106), followed by direct **Pia P2P UDP** with 7 other players (magic `32 AB 98 64`, encrypted) and two one-way packets to the NPLN host `g2122d301.lp1.p.srv.nintendo.net:34343`.

---

## 1. Provenance & integrity

* The input files were hashed first. They were then copied to `originals/` (marked read-only) and re-hashed; the hashes are identical. All work used the copies, and the inputs were never modified.
* The app's external data folder (`mkt_data`, mostly shader cache) was **not available**, so it was not analysed.
* SHA-256 of every original and generated file: [`manifest.txt`](manifest.txt).
* The APKs, the raw capture, decompiled code and extracted game assets are **not** published (see [`.gitignore`](.gitignore)). Everything else can be regenerated from your own copies with `scripts/`.

| File | SHA-256 |
|---|---|
| base.apk (90,499,986 B) | `c69366ac9d378c04069cda2751a3fc8fd78f2c6d93867e2d523dcfd0498c0c8c` |
| split_config.arm64_v8a.apk (81,651,251 B) | `f2cc97f871957d1e2a713cf5be238b6342a992242a6cae930f32c922a6a29d55` |
| PCAPdroid_29_Sep_22_19_48.pcap (5,814,424 B) | `a79774f5d15c126917b27d361cca86c8d6ded1e10cd669d89225c3aa3abe6342` |

### Tools used

Tools live in `tools/` locally and are not published; only the pip freeze is committed.

| Tool | Version | Notes |
|---|---|---|
| Python 3.12 venv | UnityPy 1.25.3, androguard 4.1.4, pyelftools 0.33, zstandard 0.25.0, cryptography 50.0.1 (+deps) | `pip install -r tools/python_requirements_freeze.txt` |
| jadx | 1.5.6 | expected in `tools/jadx` (finished with 14 per-method decompile errors, which is normal) |
| apktool | 3.0.3 | run with `-p tools/apktool_framework` so its framework cache stays in the project |
| Il2CppDumper | 6.7.46 (net6) | **not run** because there is no metadata file (Section 4) |
| Wireshark tshark / capinfos | 4.6.9 | found via `$TSHARK`, `PATH`, or the default Windows install location |
| Java runtime, .NET 6 runtime | | for jadx/apktool and Il2CppDumper |

Scripts that reproduce every output are in `scripts/` (run `01` to `08` in order, then `10_sanitize_for_publication.py`, then `09_manifest.py`).

---

## 2. App information (Part 1.2)

Source: `apk_info/apk_manifest_summary.json`, decoded manifests `apk_info/*.AndroidManifest.xml`.

| Field | Value |
|---|---|
| Package | com.nintendo.zaka |
| versionCode / versionName | 439630101 / 4.0.0 |
| minSdk / targetSdk / compileSdk | 23 / 35 / 36 |
| Launcher activity | `com.google.firebase.MessagingUnityPlayerActivity` |
| Split | `split_config.arm64_v8a` (native libs only; `com.android.vending.splits.required=true`) |
| Built with | Android Gradle Plugin 7.4.2, bundletool (`BNDLTOOL.RSA`), Play distribution stamp |
| Network security config | release trusts **system CAs only**; user CAs only under `<debug-overrides>` |
| Deep links | `npf5dbf84c0c704b31b://auth`, `npf5dbf84c0c704b31b://mii_studio` |
| Play Games APP_ID | 482624233067 |
| Firebase project | `npf-booster-a6913b7` (sender 166790037073) |

**Signing certificate** (v1 + v2 + v3, identical in both APKs; this is the Google Play App Signing key):

* Subject/Issuer: `CN=Android, OU=Android, O=Google Inc., L=Mountain View, ST=California, C=US`
* SHA-256: `ec f5 2a 0f f5 00 37 4d ae 75 55 a5 0b 4b 08 52 28 30 4a f5 de ab 01 3a bf 43 7f e4 ab 03 c9 26`
* Validity 2019-02-20 to 2049-02-20. SHA-1 and MD5 are in `apk_manifest_summary.json`.

**Permissions (14):** INTERNET, ACCESS_NETWORK_STATE, ACCESS_WIFI_STATE, ACCESS_COARSE/FINE_LOCATION, POST_NOTIFICATIONS, VIBRATE, WAKE_LOCK, WRITE_EXTERNAL_STORAGE, com.android.vending.BILLING, c2dm RECEIVE, BIND_GET_INSTALL_REFERRER_SERVICE, plus two self-declared (`...DYNAMIC_RECEIVER_NOT_EXPORTED_PERMISSION`, `...permission.C2D_MESSAGE`). See `data/permissions.csv`.

**Components** (`data/components.csv`): 10 activities (Unity player, NPF `NaAuthenticationActivity` / `MiiStudioActivity`, billing proxies, Play Games resolution), 9 services (Firebase messaging/measurement/datatransport), 6 receivers (incl. `jp.co.nintendo.booster.android.localpush.NotificationReceiver`, Unity notifications), 5 providers (FileProvider, Bugsnag, Firebase, Play Games, androidx.startup).

---

## 3. Tech stack (Part 1.4)

Full table with evidence: [`data/third_party_sdks.csv`](data/third_party_sdks.csv).

* **Engine:** Unity 2022.3.69f1, IL2CPP. Scenes: `Assets/Main/Scene/BootScene.unity`, `BoosterMain.unity`. PlayerSettings: company "Nintendo Co., Ltd.", product "Booster".
* **Nintendo / DeNA:**
  * NPF SDK (Java + `NPFSDK.dll`)
  * Sakasho core `libs2pcore.so` + `sakasho2p.dll`
  * Pia 7.2.1 (statically linked into `libil2cpp.so` + `com.nintendo.piaunity.dll`; `libjni.so` is Pia's JNI helper)
  * Nabe asset packer (`libnabe-android.so`, zstd-jni)
  * LibMessageStudio (`libms.so`, MSBT/MSBF text)
  * Sead / Uge in-house frameworks
  * `libandroidutil.so` (Booster locale/atrace helper)
* **Serialization:**
  * **protobuf** (native protobuf-lite + abseil lts_20240116 in libs2pcore; `protobuf-net.dll`, `bridging_model*.dll`)
  * **MessagePack** (`MessagePackCSharp.dll`)
  * **JSON** (Newtonsoft; NPF uses org.json)
  * Also `serializer.dll`/`schema.dll`, CoreDataConverter, CharInfoConverter (Mii), and MoonSharp Lua.
* **Networking libs:** OpenSSL 3.3.1 + POCO 1.12.5p2 (Sakasho), Java HttpURLConnection (NPF), Unity libcurl 8.10.1 (UnityWebRequest, likely CDN downloads).
* **Audio:** Wwise (`libAkSoundEngine.so`, project "Booster", generator 2023.1.14.8770).
* **Google / 3rd party:**
  * Firebase Analytics 22.4.0, FCM (+C++ SDK 12.10.0), Play Services (base 18.6.0, location 19.0.0, nearby 18.0.2, drive 17.0.0)
  * Play Games v2 17.0.0 (Unity plugin 0.11.01), Play Billing 7.1.1, Play Integrity 1.3.x, Play Core 1.8.1
  * Bugsnag Android 6.12.1 + NDK + ANR + Unity
  * Unity Mobile Notifications, NativeGallery, Sns.Twitter, Google Cloud Pub/Sub client (`pubsub.v1.json`)
  * Privacy-Sandbox adservices 1.1.0-beta11. **No ad-network SDK**; ad-ID collection is disabled (`google_analytics_adid_collection_enabled=false`, `disableUsingGoogleAdvertisingId=true`).

---

## 4. IL2CPP status (Part 1.5)

Details: [`data/il2cpp_metadata_analysis.json`](data/il2cpp_metadata_analysis.json).

| Check | Result |
|---|---|
| `libil2cpp.so` in split APK | yes, 119,284,480 B |
| `global-metadata.dat` in base.apk | **absent** (`assets/bin/Data/Managed/` holds only `Resources/mscorlib.dll-resources.dat`) |
| Magic `AF 1B B1 FA` anywhere in either APK's contents | **not found** |
| `global-metadata.dat` string in libil2cpp | not found (the loader is customised) |
| `.data` section | 27.8 MB, mean entropy 7.59. High-entropy blocks at 0x5bad020 (3.0 MB, 7.94), 0x5f20020 (4.6 MB, 7.64), 0x6c58020 (5.0 MB, 8.00). No zstd/lz4/gzip/xz signatures. |
| Exports | 241 normal `il2cpp_*` API exports (incl. `il2cpp_init`, `il2cpp_domain_get`), 1,947 exports renamed to `sym_<sha256>`, about 10,400 `nn::pia` C++ symbols |

**Conclusion:** the metadata is embedded and encrypted/obfuscated. It can't be recovered statically without reversing the loader. I tested a simple repeating-XOR hypothesis and ruled it out; the 8.0-entropy block is consistent with real encryption or compression. **Il2CppDumper was not run, so there is no dump.cs.** Because the `il2cpp_*` API exports are intact, a **runtime dump** is the practical route (Section 10).

Substitutes produced instead:
* [`data/unity_monoscripts.csv`](data/unity_monoscripts.csv): 3,901 class names (assembly/namespace/class)
* [`data/unity_network_classes.csv`](data/unity_network_classes.csv): 306 network/API-related classes
* [`strings/libil2cpp_pia_symbols.txt`](strings/libil2cpp_pia_symbols.txt), [`strings/libil2cpp_c_exports.txt`](strings/libil2cpp_c_exports.txt), [`strings/pia_izumo_npln_strings.txt`](strings/pia_izumo_npln_strings.txt)

---

## 5. Bundled content (Parts 1.3 & 1.7)

**Inventory:** [`data/file_inventory.csv`](data/file_inventory.csv) (1,081 files with sizes, compression, CRC), plus [`file_inventory_by_type.csv`](data/file_inventory_by_type.csv) and [`...by_extension.csv`](data/file_inventory_by_extension.csv).

| APK | Group | Files | Uncompressed |
|---|---|---:|---:|
| base | `assets/_nabe_/` Nabe zstd packs | 520 | 74.0 MB |
| base | Unity data (`data.unity3d`, default resources, json) | 7 | 7.9 MB |
| base | dex (classes, classes2) | 2 | 7.2 MB |
| base | res images / res xml | 221 / 194 | 1.4 / 0.2 MB |
| base | Wwise metadata (`Wwise_IDs.h`, ProjectInfo.xml) | 2 | 0.9 MB |
| base | META-INF, *.properties, protos, misc | ~110 | <1 MB |
| split | native libs (16) | 16 | 199.4 MB |

**Unity assets** (UnityPy; [`data/unity_assets.csv`](data/unity_assets.csv), [`unity_assets_summary.json`](data/unity_assets_summary.json)):
* `data.unity3d` (5,154 objects): MonoScript 3,901; TextAsset 589; Texture2D 213; MonoBehaviour 159; GameObject 63; Shader 61; Font 4 (4.5 MB); Sprite 4; AnimationClip 2; plus the usual managers (PlayerSettings, BuildSettings, ResourceManager, ...).
* The TextAssets are almost all **Mii part data** (Hair 263, Forehead 242, Cap/Nose/Nline/Mask/Faceline/Beard/Glass). Config ones: `npf` (= `assets/npf.json`), `ResourceConfig` (`mServer 8, mRevision 4396301, mSakashoEnvironment 99`), `BillingMode` (`GooglePlay`). `scripts/04_unity_assets.py` exports all 589 to `unity_export/` (game data, not published).
* `unity default resources` (85 objects) is stock Unity 2022.3.64f1 resources.

**Nabe packs (`assets/_nabe_`)**, which the in-game content ships in:
* 517 files are standard zstd frames that **require dictionary ID 0x63683640**.
* The dictionary isn't stored in plaintext. It's handed to Java at runtime via `jp.co.nintendo.nabe.AndroidUtil.SetDictionary(int, byte[])` (called from C#).
* `_catalog.bytes` (328 KB) and `_2ff16e1f.zst` (1.7 MB) are **encrypted** (entropy 8.0, no magic). `_catalog_v.bytes` = `232787236235803`.
* **Not decompressible statically** (Section 10).
* Other: `UdemaeRestoreList.encrypt_encoded.bytes` (146 KB, entropy 8.0, encrypted). `SakashoServerConfig` = `{"mEnvironment":99,"mUseAssetMaster":true}`.
* As expected, downloaded asset bundles are **not** in these files.

---

## 6. Network layer from the APK (Part 1.6)

### 6.1 Endpoint catalogue

Full list: [`data/endpoints.csv`](data/endpoints.csv) / [`endpoints.json`](data/endpoints.json). Sakasho function list: [`data/sakasho_sdk_functions.csv`](data/sakasho_sdk_functions.csv). Java classes: [`data/java_network_classes.csv`](data/java_network_classes.csv).

**A. Sakasho / Booster game API.** 80 paths in `libs2pcore.so`. The host is `api.mariokarttour.com` per the capture. Body `application/x-protobuf`. The HTTP method isn't recoverable from strings; the client has Get/Post/Delete request classes.

| Area | Paths (abridged) |
|---|---|
| System / session | `/v1/version`, `/v1/players/@me/session`, `/v1/players/@me/deactivate`, `/v1/secure_random`, `/v3/security_nonce/generate_nonce` (+ `SksV2SecurityVerifyPlayIntegrityJWT`), `/v1/suspicious_activity` |
| Master data / assets / constants | `/v1/masters`, `/v1/assets/base_url`, `/v3/server_controlled_constant/get_all_constants` |
| Player data | `/v1/players/@me/storages`, `/v1/players/_/storages/list`, `.../storages_and_inventories`, `/v3/inventory/get_inventories`, `/v3/inventory/receive_server_controlled_resources` |
| Currency / shop / subscription | `/v1/players/@me/virtual_currencies/{recover,consume_and_set_player_storages}`, `/v2/players/@me/products/{list,purchase}`, `/v1|v2/payment/received_extra_bonus...`, `/v3/limited_subscription/*`, `/v3/subscription_continuation/update_continuation` |
| Gacha ("pipes") | `/v1/booster/players/@me/rarity_box_lottery/lotteries` (Draw by ticket / VC / storage, Reset, Packages) |
| Ranked cups / ghosts | `/v3/booster/rank_race/{join,join_and_update_scores,update_score,save_term_result,list_rivals,list_player_situations,show_term_situation,show_last_joined_term_situation}`, `/v1/booster/players/@me/rank_race/ghosts[/download|/prototype_search|/prototype_destroy]` |
| Events / seasons | `/v1/booster/players/@me/event_race/terms`, `/v3/booster/event_race/list_term_statistics`, `/v3/booster/season_summary/list_summary_prepared_seasons`, `/v3/daily_bonus/update_daily_bonus`, `/v2/players/@me/login_bonuses` |
| Social | `/v1/players/@me/friends`, `.../friend_relationships`, `.../friend_candidates[/random]`, `/v1/friend_requests`, `/v1/friend_history`, `/v1/na/friend_candidates`, `.../block_lists[/add|/remove]`, `/v1/players/@me/search_tokens`, `/v1/shared_resources`, `/v1/shared_resource_messages`, gifts `/v3/booster/giftable_player_resource/*` |
| Mii | `/v3/booster/mii/{create_miis,delete_miis,list_own_miis,search_miis}` |
| Misc | `/v1/players/@me/{announcements,private_announcements,achievements[/list|/create_multi],twitter,facebook,iris/access_token}`, `/v1/na/players/@me/mission_progress`, `/v3/booster/mk8dx/fetch_play_report`, `/v3/booster/intentional_push_notification/send_push_notifications`, `/v3/limited_nintendo_account/fetch_nintendo_account` |
| **Multiplayer bootstrap** | **`/v3/booster/izumo/create_client_key`** (the key is fed to Pia `IzumoNetworkSetting_SetClientKey`) |
| Debug (server-side flags) | `/v3/debug_player/{show,set_debug_time,destroy}_debug_player` |

**B. Nintendo BaaS (NPF SDK, Java).** Host `a6913b7b80402974409b47079c29d775.baas.nintendo.com`, JSON:

* `POST /core/v1/gateway/sdk/login` (JWT assertion, Section 6.3)
* `POST /core/v1/gateway/sdk/federation`, `.../gateway/sdk/transfer_code`
* `GET|POST /core/v1/users/{id}/transfer_code`, `PATCH /core/v1/users/{id}` (json-patch), `POST /core/v1/users/{id}/link`
* `POST /bigdata/v1/analytics/events` (gzip), `GET .../events/config`
* `GET|PUT /notification/v1/push_channels/{user}/{device}`
* `POST /audit/v1/profanity_inspect`, `GET /inquiry/v1/users/{id}`
* `/vcm/v1/...` virtual-currency wallets/bundles/transactions/promo; `/subs/v1/...` subscriptions

**C. Nintendo Account:**
* `accounts.nintendo.com/connect/1.0.0/authorize` (OAuth2 + PKCE; client_id `5dbf84c0c704b31b`)
* `POST api.accounts.nintendo.com/connect/1.0.0/api/session_token` (form-encoded)
* `POST .../api/1.0.0/email/send_purchased_to_parent`
* `/mii_studio`, `/term_chooser/faq`

**D. NPLN host templates** (`libil2cpp.so`): `%s.lp1.p.srv.nintendo.net` (production; seen in capture as `g2122d301.lp1...`) and `%s.dd1.p.srv.nintendo.net` (dev).

**E. Third-party:** app-measurement.com, firebaseinstallations/firebaselogging/pubsub.googleapis.com, notify/sessions.bugsnag.com, oauth2.googleapis.com, googleadservices.com.

### 6.2 Headers, framing, serialization

* **Sakasho request headers** (libs2pcore): `X-Sks-Session-Token`, `X-Sks-Title-Id`, `X-Sks-Protocol-Version`, `X-Sks-Market`, `X-Sks-Accept-Language`, `X-Sks-Device-Timezone`, `X-Sks-Current-Time`, `X-Sks-Time-Lag`, `X-Sks-Request-Id` / `X-Sks-Req-Id`, `X-Sks-Verbose`, `User-Agent`, `Content-Type: application/x-protobuf`.
* **Session protobuf types** present natively: `Sks.Protobuf.V1.Sessions.Create.Request`, `...Create.Response`, `Sks.Protobuf.V1.Resources.Session`. Per-endpoint message schemas live on the C# side (`sakasho2p.dll`, `bridging_model.dll`, protobuf-net) inside the encrypted metadata.
* **NPF:** JSON, `Authorization: Bearer <BaaS access token>`, `User-Agent: com.nintendo.zaka/<ver> <device>/<os> NPFSDK/<ver>`, `X-HTTP-Method-Override` for PATCH/PUT over POST, gzip for analytics batches.

### 6.3 Encryption / signing of requests

* **Transport:** everything is TLS. The Sakasho client is OpenSSL 3.3.1. `libs2pcore.so` exports `SSL_read`/`SSL_write`/`SSL_CTX_set_keylog_callback`/`SSL_CTX_set_verify`, and has no embedded CA PEM (it references `/etc/ssl/cert.pem`). NPF uses the Android system trust store.
* **NPF login assertion** (`com.nintendo.npf.sdk.core.c0.m`, `o2.a`, `v4.a`):
  * `key = "com.nintendo.zaka:" + <signing cert SHA-1>`
  * `secret = TOTP(HMAC-SHA1, key, step = 600 s, digits = 8)`
  * `assertion = JWT{alg:HS256}.{iss: key, iat: now, aud: "https://<baasHost>"}` signed with `secret`
  * This is a lightweight app-authenticity check that a server can verify, and a client can reproduce, from public values.
* **Sakasho:** session token + `/v3/security_nonce/generate_nonce` + Play Integrity JWT verification (`SksV2SecurityVerifyPlayIntegrityJWT`), with `SakashoV2SecurityManager` on the C# side. I found no evidence of per-request body signing in native strings (only a POCO `HMACEngine` template), but C# can't be inspected yet.
* **Izumo / Pia:** payloads are encrypted (Section 8).

---

## 7. Capture analysis (Part 2)

Raw outputs: `pcap/` (capinfos, protocol hierarchy, conversations, DNS, TCP follows, UDP samples) and `data/` CSVs. The capture file itself is not published.

### 7.1 Summary
Raw-IP pcap from PCAPdroid (on-device VPN, so the phone's address and DNS resolver are private VPN addresses). 15,431 packets, 5.57 MB, **1046.2 s**, average 14 pkt/s.

| Protocol | Frames | Bytes |
|---|---:|---:|
| UDP | 10,278 | 1.27 MB (DNS 114; payload "data" 10,164) |
| TCP | 5,153 | 4.30 MB (TLS 1,962 frames; non-TLS "data" 224) |
| QUIC / plaintext HTTP | 0 | 0 |

244 flows (172 TCP, 72 UDP incl. 57 DNS). See [`data/connections.csv`](data/connections.csv).

### 7.2 DNS (18 names): [`pcap/dns.csv`](pcap/dns.csv)

| Name | Answer (CNAME to IPs) |
|---|---|
| api.mariokarttour.com | CloudFront `d3qu5x04mblgpc.cloudfront.net` (4 addresses) |
| pvp.mariokarttour.com | AWS NLB `nlb-prod-live-pvp-401-...elb.us-west-2.amazonaws.com` (4 addresses) |
| nat-check-0 / nat-check-1.mariokarttour.com | AWS us-west-2, 2 addresses each |
| ec2-[IP REDACTED].us-west-2.compute.amazonaws.com | [IP REDACTED] (Izumo room server; the name was delivered by pvp) |
| g2122d301.lp1.p.srv.nintendo.net | [IP REDACTED] (Google Cloud) |
| a6913b7b...baas.nintendo.com | [IP REDACTED] (Google Cloud load balancer) |
| api.accounts.nintendo.com / c-lp1.accounts.nintendo.com | Akamai |
| public-content-cdn / download-cdn / support-cdn-mariokarttour.akamaized.net | Akamai |
| announcement-resource-cdn.mariokarttour.com | Akamai `star.mariokarttour.com.edgekey.net` |
| support.mariokarttour.com | AWS ALB `alb-prod-live-web-common-401` |
| pubsub.googleapis.com, firebaselogging.googleapis.com, sessions.bugsnag.com | Google / Bugsnag |

### 7.3 TLS: [`data/tls_connections.csv`](data/tls_connections.csv), [`data/tls_server_certs.csv`](data/tls_server_certs.csv)

| SNI | Conns | Version | ALPN offered | Notes |
|---|---:|---|---|---|
| api.mariokarttour.com | 115 | TLS 1.3, TLS_AES_128_GCM_SHA256 | none | **every** connection gets a HelloRetryRequest (server picks x25519). JA4 `t13d671100_...` = the libs2pcore OpenSSL stack |
| public-content-cdn-... | 21 | TLS 1.2 | none | JA4 `t12d990700_...` (TLS 1.2-only client, likely Unity UnityWebRequest/unitytls; same for c-lp1 and download-cdn). Cert CN `a248.e.akamai.net`, SANs `*.akamaized.net` etc., DigiCert G3 ECC, valid 2025-12-22 to 2026-12-22 |
| c-lp1.accounts.nintendo.com | 10 | TLS 1.2 | none | cert `CN=*.accounts.nintendo.com, O=Nintendo Co., Ltd., L=Kyoto`, SAN `accounts.nintendo.com`, DigiCert G2 RSA, valid 2026-09-15 to 2027-04-01 |
| download-cdn-... | 1 | TLS 1.2 | none | same Akamai cert |
| baas (8), pubsub (6), api.accounts (2), support-cdn (2), announcement (2), support (1), firebaselogging (1), bugsnag (1) | | TLS 1.3 | http/1.1 | certificates encrypted (TLS 1.3); JA4 `t13d1713h1_...` = Android/Java stack |

### 7.4 Conversations & timeline (`data/connections.csv`, `pcap/conversations_*.txt`)

| t (s) | Activity |
|---|---|
| 0 to 60 | Boot: Bugsnag session, BaaS login, api.accounts, 23x api.mariokarttour.com, download-cdn, pubsub |
| 60 to 700 | Menus: periodic api.mariokarttour.com bursts, public-content-cdn image bursts (7 flows at 60/240/390 s), BaaS refresh, firebaselogging |
| 733 | Pia NAT check (nat-check-0/1) |
| 734.75 | DNS for NPLN host |
| 736.14 | TCP to **pvp.mariokarttour.com:11401** (matchmaking; lobby wait with 3 s keepalives) |
| 752.83 | pvp sends 133-byte message, **11 ms later** the client resolves and connects to room server `ec2-[IP REDACTED]:14106` (TCP + UDP) |
| 754.7 to 865 | **Race:** Pia P2P UDP with 5 sustained peers + 2 brief ones; NPLN packets at 756.3 and 865.9 |
| 880 | pvp connection ends |
| 870 to 1046 | Results/menus: support site + support-cdn, announcements, NA web (c-lp1 x10), second NAT check at ~948 s (no match followed), final API calls |

### 7.5 Plaintext HTTP
**None.** `tshark -Y "http || http2 || websocket"` gives 0 frames. The only non-TLS TCP is the Izumo binary protocol on 11401/14106 (dumped in [`pcap/plaintext_nontls_tcp.txt`](pcap/plaintext_nontls_tcp.txt), [`pcap/follow_tcp117_pvp_11401.txt`](pcap/follow_tcp117_pvp_11401.txt) and [`pcap/follow_tcp119_relay_14106.txt`](pcap/follow_tcp119_relay_14106.txt)). Its only readable content is each server's `host,port` self-identification, e.g. `ec2-[IP REDACTED].us-west-2.compute.amazonaws.com,14101` for the pvp backend node behind the NLB.

---

## 8. UDP / multiplayer findings (Part 2.5)

Per-flow stats: [`data/udp_flows.csv`](data/udp_flows.csv). Byte-position analysis: [`data/udp_header_analysis.json`](data/udp_header_analysis.json). Samples: [`pcap/udp_samples.txt`](pcap/udp_samples.txt). Rate over time: [`data/udp_p2p_rate_per_second.csv`](data/udp_p2p_rate_per_second.csv).

| Flow type | Remote port(s) | Packets | Size (payload) | Rate | Header |
|---|---|---|---|---|---|
| Pia NAT check | 33334, 34543 | 2 bursts (733 s, 948 s), 3 flows each (3-6 out, 0-3 in) | 3 B req / 9 B resp | burst | `4E 43` ("NC") + type |
| NPLN / Pia monitoring | 34343 | 2 out, 0 in | 476 / 700 B | once at session start/end | `32 AB 98 64 10` + zeros + clear structure |
| Izumo room/relay | 14106 (same port as TCP control) | 772 out / 1,060 in in 112 s | median 117, p95 241, max 598 | ~16 pkt/s | type byte `02`/`03` + 8 B tag + 8 B timestamp-nonce |
| Pia P2P peers (7) | random high ports (ephemeral/NAT) | 5 peers ~ 1,560 to 1,720 pkts each; 2 peers < 30 | median 61, p95 173, max 1,165 | 14.5-19 pkt/s per peer, outbound ~10 Hz | `32 AB 98 64 90 ...` |

**NAT check ("NC")**
* Request `4E 43 0t` (t = 0 to 3), sent in triplicate. Type 0 goes to :33334; types 1 and 2 go to nat-check-0:34543; type 3 goes to nat-check-1:34543.
* Only types 1 and 3 were answered. The reply is `4E 43 0t` + 6 bytes, identical from both servers and consistent with the reflexive IPv4 + port.
* The unanswered types (0, 2) look like filtering/mapping tests (Pia `NatCheck`/`PiaNatCheckTraits`/`NexNatCheckTraits`).

**Pia P2P header** (inferred from 5 peers, about 8k packets). `libil2cpp` reports Pia 7.2.1:

| Offset | Behaviour | Interpretation |
|---|---|---|
| 0-3 | constant `32 AB 98 64` | Pia magic |
| 4 | constant `0x90` (NPLN packets: `0x10`) | version, high bit = encrypted |
| 5 | ~34 values | flags / message class |
| 6-7 | constant per peer | destination station ID (0 before join) |
| 8-9 | constant per sender | source station ID |
| 10-11 | +1 per packet | per-link sequence number |
| 12-19 | 7 bytes constant per sender, last byte changes slowly | 8-byte nonce (sender-random prefix + counter) |
| 20+ | high entropy | probably a 16-byte AES-GCM tag + ciphertext |

Offsets 6-11 differ from older public Pia 5.x write-ups, so treat this as observed, not authoritative.

**Izumo protocol (pvp:11401 and room server:14106)**
* Both use the same framing over TCP and (for the room server) UDP:
  * **Handshake:** client sends a 76-byte type-`06` hello. Server replies `01 00 <len16> "<own host>,<port>"`.
  * **Frames:** `[b0][type/channel 0x81|0x82|0x84...][seq][ack] + 8-byte tag + 8-byte nonce + ciphertext`.
  * **Acks/keepalives:** `80 <seq> <ack> 00`, about every 3 s.
* **Verified:** bytes 1-7 of the 8-byte nonce are a little-endian **Unix timestamp in microseconds**. Client-sent values match the capture clock within about 1 ms; server-sent ones are about 0.5-0.6 s off. Byte 0 is usually `0x71`.
* The UDP relay packets use `[0x02|0x03][8 B][0x71 + 7-byte microsecond timestamp][ciphertext]`.
* Symbol evidence: `nn::pia::izumo::IzumoRelayClient`, `IzumoBackgroundProcessJob::*`, `IzumoNetworkSetting_SetClientKey`, `InitializeSessionSetting_SetEnableServerRelay`, `ResultTurn*`, `ServerRelayHeader`.
* Relay traffic volume is similar to a single peer's, so the room server probably relays or aggregates for at least one player who couldn't be reached directly, as well as carrying session control.

Multiplayer game-logic classes (from MonoScripts) include `NetworkManager`, `NetworkEngine`, `NetworkLobbyManager`, `RaceMatchingP2PManager`, `NetworkSynchronizer{Race,Time,ItemEvent,KartVehicleNet,SlotPermission,FrameRateDelay,MiscEvent,EventRaceEvent}`, `NetworkCloneManager` (Pia clone/reckoning), `NetworkMatchmakeKeyUtil`, `SakashoIzumoManager`, `SakashoP2PEventRaceManager`.

---

## 9. Hostname cross-reference (Part 2.7)

[`data/hosts_crossref.csv`](data/hosts_crossref.csv), [`data/hosts.json`](data/hosts.json), [`data/pcap_hosts.csv`](data/pcap_hosts.csv), [`data/apk_hostnames.csv`](data/apk_hostnames.csv)

| In both | Capture only | APK only (not contacted) |
|---|---|---|
| `a6913b7b...baas.nintendo.com` (npf.json) | **api.mariokarttour.com** | accounts.nintendo.com (browser flow) |
| api.accounts.nintendo.com | **pvp.mariokarttour.com** | `%s.dd1.p.srv.nintendo.net` (dev) |
| pubsub.googleapis.com | **nat-check-0/1.mariokarttour.com** | app-measurement.com, google-analytics.com |
| sessions.bugsnag.com | ec2-[IP REDACTED]...amazonaws.com (issued at runtime) | firebaseinstallations / oauth2 / www.googleapis.com |
| g2122d301.lp1.p.srv.nintendo.net (template `%s.lp1.p.srv.nintendo.net`) | c-lp1.accounts.nintendo.com | notify.bugsnag.com |
| | public-content / download / support-cdn-mariokarttour.akamaized.net | npf-booster-a6913b7.firebaseio.com / .appspot.com |
| | announcement-resource-cdn.mariokarttour.com, support.mariokarttour.com | play.google.com, googleadservices, googlesyndication |
| | firebaselogging.googleapis.com | playgames.google.com, firestore.googleapis.com (SDK strings) |

**The whole game-specific domain `mariokarttour.com` and every CDN is absent from APK plaintext.** Those hosts come from encrypted IL2CPP string literals and/or server responses (for example `/v1/assets/base_url`, and the pvp message carrying the room host).

---

## 10. Possible next steps for a private server

**Time-critical (only possible while servers are up, or while the device still has its cache):**
1. **Pull the on device data now**: `/sdcard/Android/data/com.nintendo.zaka/` and, if rooted, `/data/data/com.nintendo.zaka/`. Downloaded bundles, cached master data and the Nabe cache exist **only** there or on the CDN.
2. **Capture plaintext game traffic** if servers still answer: hook `SSL_write`/`SSL_read`, or install a keylog callback via `SSL_CTX_set_keylog_callback`, in `libs2pcore.so` (all exported). That gives the protobuf request/response bodies for every Sakasho call, which are the single most valuable artefact for a server rebuild. For NPF (Java), hook `HttpURLConnection` streams.

**Recoverable offline, after shutdown:**
3. **Runtime IL2CPP dump.** On a rooted device or emulator, the app still decrypts its metadata at `il2cpp_init` before any networking. Use Zygisk-Il2CppDumper, frida-il2cpp-bridge, or dump the decrypted metadata buffer from memory, then run Il2CppDumper on it for `dump.cs`. That unlocks:
   * the host table for `mEnvironment=99` (C# string literals)
   * **all protobuf-net contracts** (`[ProtoContract]`/`[ProtoMember]`) needed to write `.proto` files
   * HTTP methods per endpoint
   * `SakashoV2SecurityManager` logic
4. **Nabe dictionary / catalog:** hook `jp.co.nintendo.nabe.AndroidUtil.SetDictionary(int, byte[])` (plain Java) to dump the zstd dictionary (ID 0x63683640). Find the catalog/`_2ff16e1f` decryption in `Nabe.dll` after step 3.
5. **HTTP methods / exact request building** can also come from disassembling the `Sks*` exports in `libs2pcore.so` (they have symbol names). The Il2CppDumper release package includes Ghidra/IDA scripts for the dumped symbols.

**Design questions for a server:**
6. **Redirecting the client:**
   * Sakasho uses OpenSSL; where it gets its CA roots is unknown (no embedded PEM; `/etc/ssl/cert.pem` referenced). NPF uses the system store only (user CAs aren't trusted in release).
   * Options: hook `SSL_CTX_set_verify`/`X509_verify_cert`; install a system CA on a rooted test device; or patch the host literals.
   * **Re-signing the APK changes the signing cert SHA-1**, so the TOTP/JWT login key (Section 6.3) and Play Integrity change too. A private BaaS must either accept the new key or skip verification.
7. **Protobuf schemas and server responses** have to be rebuilt from `dump.cs` plus any plaintext captures. No response bodies are recoverable from this pcap (all TLS).
8. **Master data & schedules:** `/v1/masters`, `/v3/server_controlled_constant/get_all_constants`, `/v1/assets/base_url`, tour/cup/event term data, and `X-Sks-Current-Time`/`Time-Lag` handling. These are server-side and must be archived (step 1/2) or recreated.
9. **Multiplayer:**
   * **NAT check** is trivial (2 UDP ports; echo reflexive address).
   * **Izumo** (pvp + room/relay) needs the key semantics from `/v3/booster/izumo/create_client_key`, the tag/cipher scheme (8-byte tag, timestamp-based nonce) and message types. That needs `dump.cs` + Pia symbols.
   * **P2P** itself is peer-to-peer Pia and needs no server once session keys are distributed.
   * **NPLN monitoring** can be sinkholed.
   * Pia also contains `nn::pia::emulation`, `wan` and `cloud` services. Check whether a simpler service/mode can be forced for LAN/private play.
10. **Safe to sinkhole:** Firebase/pubsub/Bugsnag/app-measurement, `bigdata/v1` analytics, NPLN monitoring.
11. **Still unknown:**
    * `Iris` (`/v1/players/@me/iris/access_token`)
    * `mk8dx/fetch_play_report` (MK8DX linkage)
    * the purpose of the 1,947 `sym_<sha256>` exports
    * the build meaning of `ResourceConfig.mServer = 8`
    * whether the pvp hello (type 06) carries the Izumo client key or a derived ticket

---

## 11. File index

| Path | Contents | Published |
|---|---|---|
| `REPORT.md`, `manifest.txt`, `.gitignore` | this report; SHA-256 of inputs and generated files; publication rules | yes |
| `apk_info/` | `apk_manifest_summary.json`, decoded AndroidManifest.xml (both APKs) | yes |
| `data/` | CSV/JSON: `permissions`, `components`, `file_inventory*`, `third_party_sdks`, `endpoints`, `sakasho_sdk_functions`, `java_network_classes`, `unity_*`, `il2cpp_metadata_analysis`, `apk_network_strings_raw`, `apk_hostnames`, `connections`, `tls_connections`, `tls_server_certs`, `pcap_hosts`, `hosts_crossref`, `hosts.json`, `udp_*` | yes (IPs redacted) |
| `pcap/` | capinfos, protocol hierarchy, tshark conversation tables, DNS CSV, TCP follows, non-TLS payloads, UDP samples | yes (IPs redacted) |
| `strings/` | curated lists: Pia/Izumo/NPLN subset, Pia symbols, libil2cpp and libs2pcore exports | yes |
| `strings/*.strings.txt` | full strings dumps (ASCII + UTF-16) of every native lib, dex, arsc, Unity data | no (regenerate with `scripts/02_strings.py`) |
| `scripts/` | `01`-`08` analysis, `10_sanitize_for_publication.py` (IP/path/ASCII clean-up), `09_manifest.py` | yes |
| `tools/python_requirements_freeze.txt` | exact Python package versions | yes |
| `originals/` | read-only copies of the two APKs and the pcap | no |
| `work/` | unzipped APKs, apktool output, jadx Java sources, intermediate lists | no |
| `unity_export/` | 589 TextAssets from data.unity3d | no |
| `tools/` (rest) | venv, jadx, apktool (+framework), Il2CppDumper | no |
