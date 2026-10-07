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
- **决定性规则可复现**：多条同效果规则同时命中时，取**规则 ID 字典序
  最小者**作为 `Decision.RuleID`。该取舍只依赖规则 ID，不依赖书写顺序——
  同一请求、同一套规则，无论规则在配置里怎么排列，给出的决定性规则
  一致且可复现，不同团队写出的等价策略会看到相同的解释。
- **默认拒绝**：无任何允许规则命中时拒绝（`ReasonNoAllowRule`）。
- **属性条件**：`eq` / `ne` / `in` / `glob`（`*`、`?` 通配）。
  属性缺失、类型不符或操作符未知一律视为条件不满足，不静默放行。
- **可解释性**：`Decision` 携带决定性规则 ID、策略版本号与拒绝原因。

## 外部属性依赖

有些判断需要的属性请求方拿不到（如密级、设备合规状态），需由引擎
在评估时从外部依赖获取。策略通过 `Policy.ExternalAttrs` 声明这类属性，
引擎通过 `WithAttributeProvider` 注入获取通道：

```go
e := authz.NewEngine(
    authz.WithAttributeProvider(myProvider), // 实现 authz.AttributeProvider
)
e.Publish(&authz.Policy{
    ExternalAttrs: []string{"clearance"},
    Rules: []authz.Rule{
        {ID: "view-secret", Effect: authz.EffectAllow,
         Roles: []string{"viewer"}, Actions: []string{"read"}, Resources: []string{"doc:secret"},
         Condition: &authz.Condition{Attr: "clearance", Op: "eq", Value: "top"}},
    },
})
```

语义与保证：

- **按需获取**：只有角色/动作/资源均已匹配的候选规则引用了外部属性时，
  才会发起获取；不触碰外部属性的请求行为与既有版本完全一致。
- **单次快照**：一次评估对所需属性只获取一次（批量 `Fetch`），
  全部规则在同一份属性快照上判定，不会出现半新半旧的混合结果；
  快照是评估私有状态，不会在请求之间泄漏。
- **失败即拒绝**：Provider 报错、未配置 Provider、或返回结果缺少所需
  属性时，本次评估按 `dependency_unavailable` 降级拒绝——该原因
  **优先于任何允许规则**（存在无条件允许规则也不会放行），并与
  `no_allow_rule` / `explicit_deny` 等普通拒绝清楚区分，便于监控排障。
- **不缓存失败**：`dependency_unavailable` 结论不写入决策缓存。
  依赖是暂时性故障时，恢复后同一请求重新评估即可得到正常结论，
  失败不会被永久记住。
- **受时间预算约束**：整体评估超时（`WithEvalTimeout`）与请求 ctx
  会传入 `Fetch`；依赖慢或卡住时请求按降级拒绝返回，不无限等待，
  个别被拖住的请求不影响其它请求。Provider 实现应尊重 ctx 尽快返回。
- **Provider 要求**：并发安全；每次调用返回当次真实状态。

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
| 评估超时 / 上下文取消（含依赖获取超预算） | `eval_timeout` |
| 外部依赖属性获取失败 / 未配置 Provider / 返回缺失 | `dependency_unavailable` |
| 命中拒绝规则 | `explicit_deny` |
| 无允许规则命中 | `no_allow_rule` |

其中 `dependency_unavailable` 表示评估**没有完成**，与"评估完成但
确实没权限"（`no_allow_rule` / `explicit_deny`）严格区分；它优先于
允许规则，且不会被缓存。

## 配置项

| Option | 默认值 | 说明 |
|---|---|---|
| `WithEvalTimeout(d)` | 100ms | 单次评估超时（含依赖获取），超时降级拒绝 |
| `WithCacheSize(n)` | 1024 | 决策缓存容量上限 |
| `WithAttributeProvider(p)` | 无 | 外部属性依赖；策略声明 `ExternalAttrs` 时必需 |

策略侧新增 `Policy.ExternalAttrs []string`：声明需由引擎从外部依赖
获取的属性名。不声明即不涉及外部依赖，既有配置无需任何迁移。

## 测试

```sh
go test ./authz/ -race -count=1
```

覆盖：多级角色继承（含循环继承安全性）、属性条件、拒绝优先、
规则顺序无关性（随机打乱 100 次，含决定性规则 ID 一致性）、
并发发布与缓存失效、热更新一致性、超时与上下文取消降级、
小容量缓存并发重建、依赖缺失拒绝且原因可区分、依赖缺失时
允许规则不放行、依赖恢复后结论恢复、依赖并发与时好时坏下
结论一致、单次评估单次依赖快照、慢依赖受时间预算约束。
