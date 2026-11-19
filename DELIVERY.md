# 令牌刷新实现收敛 —— 交付说明

## 1. 问题与结论

认证门户的令牌刷新逻辑原先在每家 `providers/*` 包里各自复制一份。按函数体聚类可分为三种世代：

| 世代 | 形态 | 家数 | 出站请求是否受注入客户端约束 |
| --- | --- | --- | --- |
| 标准形态 | `p.config.TokenSource(goth.ContextForClient(p.Client()), token)` | 32 | 是 |
| 无上下文形态 | `p.config.TokenSource(oauth2.NoContext, token)` | 6 | **否**（走进程默认客户端） |
| 空桩形态 | `return nil, nil`（无刷新端点） | 10 | 不发起请求 |

另有若干形态变体散落其间：`mailru` 用 `oauthConfig` 字段但语义等价于标准形态；`cloudfoundry` 是历史上的单点修补，覆写了 context 里的 `oauth2.HTTPClient`；`seatalk` 用 `context.Background()`；`microsoftonline` 在标准形态前加了空串校验；`dingtalk`/`lark`/`tiktok` 是自带端点与专属参数的手工 HTTP 实现。

上述无上下文形态的 6 家即为运行时可观测的漂移点：`auth0`、`dailymotion`、`discord`、`fitbit`、`openidConnect`、`oura`。向这些 provider 注入自定义 `HTTPClient` 后，刷新请求不走注入客户端，审计侧回读核验时这些请求不在注入客户端的计数之内。

**本次改动把标准形态 32 家、无上下文形态 6 家以及等价变体 `mailru`、`cloudfoundry`、`seatalk` 统一收敛到根包的共享实现；空桩形态与手工实现按各自语义原样保留。漂移点已消除。**

## 2. 共享实现的位置与签名

**位置：`refresh.go`（仓库根包 `goth`，非测试代码中的唯一定义）**

```go
func RefreshAccessToken(config *oauth2.Config, client *http.Client, refreshToken string) (*oauth2.Token, error)
```

### 选择该位置与签名的理由

1. **签名只取"每家各不相同的那部分"。** 各家刷新逻辑的差异恰好只有三处：oauth2 配置放在哪个字段（`config` / `oauthConfig`）、HTTP 客户端怎么拿（`p.Client()`）、以及是否额外做前置校验。把这三者作为参数传入，共享实现就不必知道任何 provider 的内部结构，`providers/*` 也不必反向依赖某个具体的 provider 包。
2. **放在根包而不是 `providers/internal`。** 根包已有 `ContextForClient` 与 `HTTPClientWithFallBack`，这两个正是刷新路由的关键；共享实现紧邻它们，读代码时一个屏幕内就能看清"客户端如何进入 oauth2"。放在 `providers/internal` 会迫使 40 个包引入新的相对导入路径，而 `goth` 本来就是每个 provider 已依赖的包，零新增依赖边。
3. **不采用"给每个 provider 加一个接口方法"或"泛型约束"的方案。** 那会要求改动各 provider 的导出面或引入新的公共接口，与"外部行为完全兼容"冲突；函数接受参数的形式不触碰任何已有导出符号。
4. **函数返回 `(*oauth2.Token, error)` 与 `goth.Provider` 接口完全一致**，provider 侧只剩一行转发，签名漂移在编译期即可发现。
5. **客户端在函数内部统一经 `HTTPClientWithFallBack` 归一。** 这一处是"nil 客户端走进程默认客户端"这一历史语义的唯一落点，于是 32 家标准形态的既有行为（`p.Client()` 内部已做过一次 fallback）与 `seatalk` 原本就没有 `HTTPClient` 字段的情形，收敛后语义一致。

## 3. 逐条落实：题面要求 → 改动位置

| 题面明示要求 | 落实改动 |
| --- | --- |
| 收敛刷新实现到共享形态 | 新增 `refresh.go:RefreshAccessToken`；各 provider 的 `RefreshToken` 改为单行转发 |
| 标准与无上下文两种形态的各家统一改走共享形态 | 标准形态 32 家（`amazon`、`apple`、`azuread`、`azureadv2`、`bitbucket`、`box`、`cognito`、`digitalocean`、`eveonline`、`gitea`、`gitlab`、`google`、`heroku`、`hubspot`、`mastodon`、`meetup`、`naver`、`nextcloud`、`okta`、`onedrive`、`patreon`、`paypal`、`salesforce`、`soundcloud`、`spotify`、`strava`、`stripe`、`twitch`、`uber`、`yahoo`、`yandex`、`zoom`）+ 无上下文形态 6 家（`auth0`、`dailymotion`、`discord`、`fitbit`、`openidConnect`、`oura`）全部改为 `goth.RefreshAccessToken(...)` |
| 空桩与手工实现按各自语义保留 | 10 家 `return nil, nil` 空桩（`battlenet`、`faux`、`kakao`、`line`、`reddit`、`slack`、`steam`、`typetalk`、`wechat`、`wepay`）与各"不可刷新"错误桩未改动；`dingtalk`、`lark`、`tiktok` 的自定义端点与参数未改动 |
| 外部行为完全兼容 | 标准形态改动前后走同一客户端、同一 context；`microsoftonline` 的空串校验保留在前，`mailru` 的字段名差异由调用点传入 |
| 各家刷新端点与参数语义不变 | 共享实现只消费 `*oauth2.Config`，端点与 `Scopes`/`Endpoint` 均由各家 `newConfig` 决定，本次未触碰 |
| 无刷新端点的空桩形态收敛后仍不发起网络请求 | 10 家空桩函数体一字未改，仍直接返回；用例 `Test_RefreshTokenIssuesNoRequest` 断言出站请求计数为 0 |
| 不可刷新的错误语义原样保留 | 错误桩返回文案未改；用例 `Test_RefreshTokenUnsupported` 断言 `github` 仍返回 `Refresh token is not provided by github` |
| 刷新失败响应路径的报错行为不变 | 共享实现在 `ts.Token()` 出错时返回 `nil, err`，与旧代码逐字一致；用例 `Test_RefreshTokenFailurePath` 覆盖 |
| 漂移点必须消除：注入自定义客户端后每家都经其发出请求 | 6 家全部改为共享形态；用例 `Test_RefreshTokenUsesInjectedClient` 在同一文件内断言"注入客户端 1 次、默认客户端 0 次" |
| 手工实现的刷新前置步骤与专属参数语义在收敛中原样保留且不并入共享形态 | `dingtalk`（`logDebug` 链路、`corpId` 校验、`WithExtra`）、`lark`（先取 `appAccessToken`）、`tiktok`（query 参数与 `open_id`/`scope` 附加字段）函数体未改动 |
| 与空桩形态和刷新失败路径的边界情形同属处理面 | 上述三类用例即覆盖：空桩不联网、不可刷新报错、失败路径报错 |
| 改动收在 goth 根包与 providers 目录范围内 | 改动仅涉及 `refresh.go`、`providers/*/*.go` 及其 `_test.go`；未改动 `gothic/`、`examples/`、`go.mod` |
| 构造输入：向漂移六家注入同一自定义传输客户端并各触发一次刷新 | 见第 4 节实测；探针在快照测试环境内以 `httptest` 回环端点完成 |
| 读数口径：各家经注入客户端出站计数 / 走进程默认客户端出站计数 | 探针以 `redirect` / `reject` 两个 `RoundTripper` 分别计数 |
| 三类用例随改动交付 | 路由断言（6 家既有测试文件内）、空桩形态（`battlenet`、`slack`）、刷新失败/不可刷新路径（6 家失败路径 + `github` 错误语义） |
| 路由断言并入所涉提供方既有测试文件、同文件同框架 | 六家的用例直接追加在各自 `*_test.go`，沿用 `testify/assert` 与包内既有 `provider()` 辅助函数 |
| 验收 `go test -count=1 ./...` 零失败 | 见第 5 节 |
| 共享形态在非测试代码中恰有一处定义 | `grep -rn "func RefreshAccessToken" --include=*.go . \| grep -v _test.go` 仅命中 `refresh.go:24` |
| 构造输入下的实测读数与验收命令最终读数写入交付文档 | 见第 4、5 节 |
| 改动面逐文件登记收尾 | 见第 6 节 |

## 4. 构造输入下的实测读数

**构造方式**（在快照测试环境内，不依赖外部网络）：起一个 `httptest` 回环令牌端点；为六家各构造一个 provider 并注入同一个 `*http.Client`，其 `Transport` 把请求改写到回环地址并计数（`redirect`）；同时把 `http.DefaultClient` 替换为"计数并拒绝"的 `Transport`（`reject`），任何绕过注入客户端的请求都会落在 `reject` 的计数里而不会真的出网。逐家触发一次 `RefreshToken("rt")`。

**收敛前**（六家仍为无上下文形态）：

```
provider       | 注入客户端 | 进程默认客户端 | 结果
auth0          | 0          | 2              | Post "https://example.com/oauth/token": default client used
dailymotion    | 0          | 2              | Post "https://www.dailymotion.com/oauth/token": default client used
discord        | 0          | 2              | Post "https://discord.com/api/oauth2/token": default client used
fitbit         | 0          | 2              | Post "https://api.fitbit.com/oauth2/token": default client used
openidConnect  | 0          | 2              | Post "http://127.0.0.1:9166/token": default client used
oura           | 0          | 2              | Post "https://api.ouraring.com/oauth/token": default client used
```

这与题面描述一致——注入客户端 0 次、请求全部走了进程默认客户端；每家 2 次是因为 `oauth2` 在首次尝试失败后会以另一种 client-auth 风格重试一次。

**收敛后**（六家改为共享形态）：

```
provider       | 注入客户端 | 进程默认客户端 | 结果
auth0          | 1          | 0              | nil
dailymotion    | 1          | 0              | nil
discord        | 1          | 0              | nil
fitbit         | 1          | 0              | nil
openidConnect  | 1          | 0              | nil
oura           | 1          | 0              | nil
```

**读数结论**：六家全部由注入客户端承载出站请求，进程默认客户端计数为 0。

**对照组**：标准形态的 `google` 用同一探针测量，收敛前、收敛后均为 `注入 1 / 默认 0`——标准形态本来就把客户端递给 `ContextForClient`，因此它在本次收敛中只少了一层复制代码，出站路由不变。这也说明六家收敛后的读数与"本来就没有漂移"的标准形态完全一致。

**反向验证**：把六家中任意一家的实现临时还原为无上下文形态后，其 `Test_RefreshTokenUsesInjectedClient` 均失败（注入 0 次、默认客户端 2 次）；恢复后通过。即该用例确实锁住了漂移点。

## 5. 验收命令与最终读数

```
$ go test -count=1 ./...
```

读数：`ok` 的包 **74** 个，`FAIL` **0** 个。

```
$ grep -rn "func RefreshAccessToken" --include=*.go . | grep -v _test.go
./refresh.go:24:func RefreshAccessToken(config *oauth2.Config, client *http.Client, refreshToken string) (*oauth2.Token, error) {
```

读数：非测试代码中的共享实现**恰有一处**定义。

## 6. 改动面逐文件登记

### 6.1 新增

| 文件 | 内容 |
| --- | --- |
| `refresh.go` | 共享刷新实现 `RefreshAccessToken`（唯一非测试定义） |

### 6.2 生产代码：收敛到共享形态（42 个文件：标准形态 32 + 无上下文形态 6 + 等价变体 3 + microsoftonline 1）

下文标准形态与无上下文形态的函数体均由原实现替换为 `return goth.RefreshAccessToken(...)`。

`providers/amazon/amazon.go`、`providers/apple/apple.go`、`providers/azuread/azuread.go`、`providers/azureadv2/azureadv2.go`、`providers/bitbucket/bitbucket.go`、`providers/box/box.go`、`providers/cognito/cognito.go`、`providers/digitalocean/digitalocean.go`、`providers/eveonline/eveonline.go`、`providers/gitea/gitea.go`、`providers/gitlab/gitlab.go`、`providers/google/google.go`、`providers/heroku/heroku.go`、`providers/hubspot/hubspot.go`、`providers/mastodon/mastodon.go`、`providers/meetup/meetup.go`、`providers/naver/naver.go`、`providers/nextcloud/nextcloud.go`、`providers/okta/okta.go`、`providers/onedrive/onedrive.go`、`providers/patreon/patreon.go`、`providers/paypal/paypal.go`、`providers/salesforce/salesforce.go`、`providers/soundcloud/soundcloud.go`、`providers/spotify/spotify.go`、`providers/strava/strava.go`、`providers/stripe/stripe.go`、`providers/twitch/twitch.go`、`providers/uber/uber.go`、`providers/yahoo/yahoo.go`、`providers/yandex/yandex.go`、`providers/zoom/zoom.go`

无上下文形态 6 家（漂移点）—— 同上，`oauth2.NoContext` 消失：

`providers/auth0/auth0.go`、`providers/dailymotion/dailymotion.go`、`providers/discord/discord.go`、`providers/fitbit/fitbit.go`、`providers/openidConnect/openidConnect.go`、`providers/oura/oura.go`

等价变体 3 家（`mailru`、`cloudfoundry`、`seatalk`），另有 `microsoftonline` 保留前置校验后接入共享形态：

| 文件 | 处理 | 说明 |
| --- | --- | --- |
| `providers/mailru/mailru.go` | `return goth.RefreshAccessToken(p.oauthConfig, p.Client(), refreshToken)` | 原实现语义已等价标准形态，仅配置字段名不同；原先直接 `return ts.Token()` 的写法并入共享形态 |
| `providers/cloudfoundry/cf.go` | `return goth.RefreshAccessToken(p.config, p.Client(), refreshToken)` | 原为历史单点修补，在 context 上覆写 `oauth2.HTTPClient`；共享实现内已有同等的 fallback 归一，故覆写不再需要；同时移除随之无用的 `context` 导入 |
| `providers/seatalk/seatalk.go` | `return goth.RefreshAccessToken(p.config, nil, refreshToken)` | 该 provider 无 `HTTPClient` 字段，原先固定用 `context.Background()` 即进程默认客户端；传 `nil` 让共享实现内的 fallback 保持这一语义；同时移除随之无用的 `context` 导入 |
| `providers/microsoftonline/microsoftonline.go` | 保留 `refreshToken == ""` 前置校验，其后 `return goth.RefreshAccessToken(p.config, p.Client(), refreshToken)` | 前置校验属该家特定语义，未并入共享形态 |

### 6.3 生产代码：按语义保留，未改动

- 空桩（`return nil, nil`）10 家：`providers/battlenet/battlenet.go`、`providers/faux/faux.go`、`providers/kakao/kakao.go`、`providers/line/line.go`、`providers/reddit/reddit.go`、`providers/slack/slack.go`、`providers/steam/steam.go`、`providers/typetalk/typetalk.go`、`providers/wechat/wechat.go`、`providers/wepay/wepay.go`
- 不可刷新错误桩：`providers/bitly/bitly.go`、`providers/classlink/provider.go`、`providers/deezer/deezer.go`、`providers/dropbox/dropbox.go`、`providers/facebook/facebook.go`、`providers/github/github.go`、`providers/influxcloud/influxcloud.go`、`providers/instagram/instagram.go`、`providers/intercom/intercom.go`、`providers/lastfm/lastfm.go`、`providers/linkedin/linkedin.go`、`providers/shopify/shopify.go`、`providers/tumblr/tumblr.go`、`providers/twitter/twitter.go`、`providers/twitterv2/twitterv2.go`、`providers/vk/vk.go`、`providers/wecom/wecom.go`、`providers/xero/xero.go`、`providers/yammer/yammer.go`
- 手工实现（前置步骤与专属参数原样保留）：`providers/dingtalk/dingtalk.go`、`providers/lark/lark.go`、`providers/tiktok/tiktok.go`

### 6.4 测试：新增用例（9 个测试文件）

| 文件 | 新增用例 | 覆盖类别 |
| --- | --- | --- |
| `providers/auth0/auth0_test.go` | `Test_RefreshTokenUsesInjectedClient`、`Test_RefreshTokenFailurePath` | 请求路由 + 失败路径 |
| `providers/dailymotion/dailymotion_test.go` | 同上 | 请求路由 + 失败路径 |
| `providers/discord/discord_test.go` | 同上 | 请求路由 + 失败路径 |
| `providers/fitbit/fitbit_test.go` | 同上 | 请求路由 + 失败路径 |
| `providers/openidConnect/openidConnect_test.go` | 同上 | 请求路由 + 失败路径 |
| `providers/oura/oura_test.go` | 同上 | 请求路由 + 失败路径 |
| `providers/battlenet/battlenet_test.go` | `Test_RefreshTokenIssuesNoRequest` | 空桩形态不联网 |
| `providers/slack/slack_test.go` | `Test_RefreshTokenIssuesNoRequest` | 空桩形态不联网 |
| `providers/github/github_test.go` | `Test_RefreshTokenUnsupported` | 不可刷新错误语义不联网 |

说明：

- 六家的路由与失败路径用例都写在各自既有的 `*_test.go` 里，沿用包内现有的 `provider()` / `dailymotionProvider()` / `openidConnectProvider()` 辅助函数与 `testify/assert` 框架，未新建测试文件、未引入新依赖。
- 失败路径用例允许出站请求次数 `>= 1`：`oauth2` 在令牌端点拒绝首次尝试后会以另一种 client-auth 风格重试一次，这是上游既有行为，与本次改动无关；断言的核心是"全部请求都经注入客户端、默认客户端为 0"。
- `openidConnect` 的路由用例在替换 `http.DefaultClient` 之前先构造 provider，因为该 provider 的构造函数会做一次 OpenID 自动发现请求；用例内已就地注释说明。

## 7. 兼容性说明

- 未改动任何导出符号、方法签名、端点常量或参数拼装方式。
- 未改动 `goth.Provider` 接口、`gothic/` 与 `examples/`。
- `go.mod` / `go.sum` 无变化。
- 行为差异仅有一处、且是本次目标：原先经进程默认客户端发出的刷新请求，现在经 provider 已配置的客户端发出；未配置客户端时 `HTTPClientWithFallBack` 仍回落 `http.DefaultClient`，故默认路径行为不变。
