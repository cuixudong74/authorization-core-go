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
- **决定性规则确定可复现**：同一效果有多条规则命中时，取规则 ID 字典序
  最小者作为 `Decision.RuleID`。因此等价的策略无论规则书写顺序如何，
  对同一请求给出的决定性规则完全一致。
- **默认拒绝**：无任何允许规则命中时拒绝（`ReasonNoAllowRule`）。
- **属性条件**：`eq` / `ne` / `in` / `glob`（`*`、`?` 通配）。
  属性缺失、类型不符或操作符未知一律视为条件不满足，不静默放行。
- **可解释性**：`Decision` 携带决定性规则 ID、策略版本号与拒绝原因。

## 外部属性依赖

有些判断需要的属性请求方拿不到（如安全等级、资源归属），需要引擎
自己向外部依赖获取。用法：

```go
// 1. 实现提供者（必须并发安全，应尊重 ctx 取消）
type clearanceProvider struct{ /* ... */ }
func (p *clearanceProvider) FetchAttributes(ctx context.Context, req authz.Request, attrs []string) (map[string]any, error) {
    // 从用户中心/资源目录获取 attrs 列出的属性
}

// 2. 配置引擎
e := authz.NewEngine(authz.WithAttributeProvider(&clearanceProvider{}))

// 3. 策略中声明哪些属性来自外部依赖
e.Publish(&authz.Policy{
    ExternalAttributes: []string{"clearance"},
    Rules: []authz.Rule{
        {ID: "read-secret", Effect: authz.EffectAllow,
         Roles: []string{"*"}, Actions: []string{"read"}, Resources: []string{"doc:secret"},
         Condition: &authz.Condition{Attr: "clearance", Op: "eq", Value: "top"}},
    },
})
```

语义：

- **按需获取**：仅当某条角色/动作/资源均匹配的规则，其条件引用了
  `ExternalAttributes` 中声明的属性、且请求方未携带该属性时，才调用
  `FetchAttributes`。请求方已携带的属性直接使用，不触发获取；
  不声明 `ExternalAttributes` 的策略完全不涉及提供者，行为与之前一致。
- **失败即拒绝**：获取报错、结果缺少必需属性、或未配置提供者而策略
  需要外部属性时，直接拒绝并返回 `ReasonDependencyUnavailable`。
  **该结论优先于任何允许规则**——只要评估必需的关键依赖没到位，
  即使存在能匹配的允许规则也绝不放行。`Decision.RuleID` 记录被依赖
  卡住的规则（多条时取 ID 字典序最小者）。
- **单次评估一致性**：每次评估对必需属性只获取一次，整个评估使用同一份
  结果，不会出现半新半旧的混合；不同请求的获取相互独立，结论不会串扰。
- **失败不缓存**：`dependency_unavailable` 结论绝不写入缓存。依赖只是
  暂时故障时，恢复后同一请求重新评估即可得到正常结论。
- **取值即缓存键**：获取成功时，缓存键包含本次取到的外部属性值，
  依赖取值变化后不会复用旧结论。
- **时间预算**：获取与评估共享 `WithEvalTimeout` 预算。依赖慢或卡住时
  按 `eval_timeout` 降级拒绝，请求不会无限等待；个别请求被拖住
  不影响其它请求的评估。

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
| 评估超时 / 上下文取消 / 依赖卡住超预算 | `eval_timeout` |
| 外部依赖获取失败、结果不完整或必需属性缺失 | `dependency_unavailable` |
| 命中拒绝规则 | `explicit_deny` |
| 无允许规则命中 | `no_allow_rule` |

`dependency_unavailable` 表示评估**未能完成**（关键依赖没到位），
与"评估完成但确实没权限"（`explicit_deny` / `no_allow_rule`）明确区分，
监控与排障时可分别告警。该结论优先于允许、不写入缓存，依赖恢复后
同一请求重新评估即得到正常结论。

## 配置项

| Option | 默认值 | 说明 |
|---|---|---|
| `WithEvalTimeout(d)` | 100ms | 单次评估超时（含外部属性获取），超时降级拒绝 |
| `WithCacheSize(n)` | 1024 | 决策缓存容量上限 |
| `WithAttributeProvider(p)` | 无 | 外部属性提供者；仅策略声明 `ExternalAttributes` 且请求方未携带对应属性时调用 |

策略级配置：`Policy.ExternalAttributes` 声明需从外部依赖获取的属性名
（发布时校验：非空、不重复）。不声明该字段的现有策略与配置无需任何迁移。

## 测试

```sh
go test ./authz/ -race -count=1
```

覆盖：多级角色继承（含循环继承安全性）、属性条件、拒绝优先、
规则顺序无关性（随机打乱 100 次，含决定性规则 RuleID 一致性）、
并发发布与缓存失效、热更新一致性、超时与上下文取消降级、
小容量缓存并发重建、外部依赖失败/不完整/未配置时拒绝且原因可区分、
依赖缺失优先于允许规则、依赖恢复后结论恢复且失败不缓存、
依赖取值变化不复用旧结论、并发与时好时坏依赖下结论与当次状态一致、
依赖卡住时按预算降级且不阻塞其它请求。
