# authorization-core-go

统一授权决策核心：把散落在各服务的权限判断（角色继承、属性条件、通配
规则、拒绝优先）收敛到一处，保证策略热更新期间不混入新旧结论、缓存失效
期间不放行越权请求、任何依赖异常都默认拒绝并给出可区分的拒绝原因。

## 安装

```bash
go get github.com/cuixudong74/authorization-core-go
```

模块分为两个包：

- `policy`：策略模型、纯函数决策、版本化存储。无外部依赖，可独立嵌入。
- `authz`：授权引擎，在 `policy` 之上提供超时控制、决策缓存、依赖降级与
  发布联动失效。

## 快速开始

```go
store := policy.NewStore()
cache := authz.NewCache()
engine := authz.NewEngine(store, cache, authz.Config{
    EvalTimeout: 200 * time.Millisecond,
    CacheEnabled: true,
    CacheTTL:    30 * time.Second, // 0 表示仅在发布时失效
}, nil)

// 发布策略（版本号由 store 单调分配）
v, err := engine.Publish(&policy.Policy{
    Roles: []policy.Role{
        {Name: "guest"},
        {Name: "member", Inherits: []string{"guest"}},
        {Name: "admin", Inherits: []string{"member"}},
    },
    Rules: []policy.Rule{
        {ID: "member-read", Effect: policy.EffectAllow, Roles: []string{"member"},
            Resource: "doc:*", Action: "read"},
        {ID: "admin-all", Effect: policy.EffectAllow, Roles: []string{"admin"},
            Resource: "doc:*", Action: "*"},
        {ID: "deny-secret", Effect: policy.EffectDeny, Roles: []string{"admin"},
            Resource: "doc:secret", Action: "*"},
    },
})

d := engine.Authorize(context.Background(), policy.Request{
    Subject:      "u1",
    SubjectRoles: []string{"admin"},
    Resource:     "doc:secret",
    Action:       "read",
})
// d.Allowed == false, d.Reason == "explicit_deny", d.Version == v
```

## 决策语义

1. **默认拒绝（default deny）**：只有存在匹配的允许规则时才可能放行；
   没有任何规则匹配时一律拒绝。
2. **拒绝优先（deny-overrides）**：一次评估会检查全部规则，任意一条
   拒绝规则命中即整体拒绝，即使同时存在多条允许规则。
3. **顺序无关**：结论与规则书写顺序无关。所有匹配规则都会被纳入判断；
   当多条同效规则命中时，按规则 ID 字典序取第一条写入决策，保证冲突
   场景下结论确定、可解释（`Decision.RuleID` 即决定结果的规则）。
4. **角色继承**：`Role.Inherits` 声明该角色继承哪些角色的权限（传递
   展开）。请求的 `SubjectRoles` 会被展开为完整角色集后再匹配规则；
   角色继承图存在环时策略校验失败，拒绝发布。
5. **通配规则**：`Resource` / `Action` 支持 `*` 通配符，匹配任意长度
   字符序列（如 `doc:*` 匹配 `doc:1`、`*` 匹配全部）；无 `*` 时精确
   匹配。
6. **属性条件**：同一规则的多个条件为“与”关系，全部成立规则才命中。
   支持的操作符：

   | 操作符 | 含义 |
   | --- | --- |
   | `eq` / `ne` | 字符串相等 / 不等 |
   | `gt` / `lt` / `ge` / `le` | 数值比较（按浮点解析，非数值则条件不成立） |
   | `in` | 属性值等于逗号分隔列表中的某一项 |
   | `prefix` / `suffix` / `contains` | 前缀 / 后缀 / 包含 |
   | `exists` | 属性存在即成立 |

   条件引用的属性缺失时该条件不成立（规则不命中）；若策略声明了
   `RequiredAttributes` 而请求缺少，则直接判为依赖缺失拒绝（见降级）。

## 版本规则

- 版本号由存储单调分配（从 1 开始），`Policy.Version` 随决策返回，可用于
  审计与回放。
- 发布即**原子指针切换**：读者任一时刻通过 `Store.Current()` 只能看到某
  个已提交的完整版本，发布过程中的半成品对请求不可见；非法策略（校验
  失败）不会被安装，存储保持不变。
- **进行中的请求不混版本**：`Authorize` 进入时先快照当前策略版本，整次
  评估（含属性提供方调用）都基于该快照。发布切换后，已在途的请求继续
  使用旧版本，切换完成后的新请求使用新版本。

## 缓存语义

- 缓存键由「策略版本 + 请求指纹（角色、资源、动作、属性排序后规范化）」
  组成，条目记录其评估时的策略版本。
- **发布即失效**：`Engine.Publish` 成功后立即清空全部缓存条目；即使不清
  空，条目的版本校验也会阻止旧版本结论被返回。
- 缓存条目不可变（写入后不再修改），并发读写不会出现脏读；缓存未命中
  时重新评估，任何情况下都不因缓存故障放行。
- `CacheTTL` 仅控制条目有效期；`<=0` 表示只在发布时失效。

## 降级与拒绝原因

所有异常路径一律拒绝，`Decision.Reason` 给出可区分的原因：

| Reason | 触发场景 |
| --- | --- |
| `allow` | 命中允许规则且无拒绝规则 |
| `explicit_deny` | 命中任意拒绝规则（拒绝优先） |
| `no_matching_rule` | 无规则命中，默认拒绝 |
| `policy_missing` | 尚未发布任何策略，或请求的版本不存在 |
| `dependency_missing` | 属性提供方返回错误，或缺少 `RequiredAttributes` 声明的必需属性 |
| `timeout` | 评估（含属性提供方调用）超过 `EvalTimeout` |
| `invalid_request` | 请求缺少 subject/resource/action |
| `invalid_policy` | 策略未通过校验（环、未知角色、未知操作符等） |

## 配置项（`authz.Config`）

| 字段 | 默认值 | 说明 |
| --- | --- | --- |
| `EvalTimeout` | `2s` | 单次评估（含依赖调用）的超时时间，超时返回 `timeout` 拒绝 |
| `CacheEnabled` | `false` | 是否启用决策缓存 |
| `CacheTTL` | `0`（永不过期） | 缓存条目有效期，仅在发布时失效 |

## 测试

```bash
go test ./... -race
```

覆盖：多级角色继承、属性条件、通配规则、拒绝优先与顺序无关、默认拒绝、
策略校验（角色环等）、策略缺失/依赖缺失/超时降级、缓存命中与发布失效、
并发发布与评估（`-race`）、在途请求保持旧快照、缓存清空期间结论始终与
所属版本一致。
