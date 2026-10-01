# authorization-core-go

统一的授权决策核心。将各服务分散维护的权限判断（角色继承、属性条件、
拒绝优先、缓存失效）收敛到一处，保证结论确定、可解释、并发安全。

## 快速开始

```go
e := authz.NewEngine(
    authz.WithEvalTimeout(50*time.Millisecond),
    authz.WithCacheSize(4096),
)

version, err := e.Publish(&authz.Policy{
    Roles: map[string][]string{
        "admin": {"editor"},      // admin 继承 editor
        "editor": {"viewer"},
    },
    Rules: []authz.Rule{
        {ID: "view", Effect: authz.EffectAllow,
         Roles: []string{"viewer"}, Actions: []string{"read"}, Resources: []string{"doc:*"}},
        {ID: "no-secret", Effect: authz.EffectDeny,
         Roles: []string{"*"}, Actions: []string{"read"}, Resources: []string{"doc:secret"},
         Condition: &authz.Condition{Attr: "clearance", Op: "ne", Value: "top"}},
    },
})

d := e.Authorize(ctx, authz.Request{
    Subject: "alice", Roles: []string{"admin"},
    Action: "read", Resource: "doc:1",
    Attributes: map[string]any{"dept": "eng"},
})
// d.Allow / d.Reason / d.RuleID / d.Version / d.FromCache
```

## 决策语义

- **规则命中**：角色、动作、资源、条件四项全部满足。角色按继承关系取
  传递闭包后匹配；动作与资源支持精确匹配、`*` 全匹配和 `prefix:*` 前缀匹配。
- **拒绝优先（deny-overrides）**：任意一条拒绝规则命中即整体拒绝
  （`ReasonExplicitDeny`），即使同时存在允许规则。结论只取决于规则集合，
  **与规则书写顺序无关**；多级继承与通配叠加的结果与逐条展开一致。
- **默认拒绝**：无任何允许规则命中时拒绝（`ReasonNoAllowRule`）。
- **属性条件**：`eq` / `ne` / `in` / `glob`（`*`、`?` 通配）。
  属性缺失、类型不符或操作符未知一律视为条件不满足，不静默放行。
- **可解释性**：`Decision` 携带决定性规则 ID、策略版本号与拒绝原因。

## 版本与发布规则

- `Publish` 先整体校验策略（规则 ID、Effect、条件操作符），校验失败
  **整体拒绝发布**，旧版本继续生效。
- 发布是原子指针替换：读取方任一时刻只能看到某个已提交的完整版本，
  发布过程中的半成品对任何请求不可见。
- 版本号单调递增。单次 `Authorize` 只读取一次快照，正在评估的请求
  不会得到新旧混合的结果；切换完成后新请求按新版本评估。

## 缓存与失效

- 缓存键为 `(策略版本, 请求指纹)`：策略变更后旧版本结论天然不可达；
  发布时还会精准失效旧版本条目，双保险。
- 缓存读写全程加锁，无半成品条目，不会脏读。
- 容量超限触发清空重建；重建期间未命中即重新评估，**只多算、不放行**。

## 降级策略（一律默认拒绝，原因可区分）

| 场景 | Reason |
|---|---|
| 从未发布过策略 | `policy_missing` |
| 评估超时 / 上下文取消 | `eval_timeout` |
| 命中拒绝规则 | `explicit_deny` |
| 无允许规则命中 | `no_allow_rule` |

## 配置项

| Option | 默认值 | 说明 |
|---|---|---|
| `WithEvalTimeout(d)` | 100ms | 单次评估超时，超时降级拒绝 |
| `WithCacheSize(n)` | 1024 | 决策缓存容量上限 |

## 测试

```sh
go test ./authz/ -race -count=1
```

覆盖：多级角色继承（含循环继承安全性）、属性条件、拒绝优先、
规则顺序无关性（随机打乱 100 次）、并发发布与缓存失效、
热更新一致性、超时与上下文取消降级、小容量缓存并发重建。
