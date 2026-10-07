package authz

import "context"

// AttributeProvider 从外部依赖（如用户属性服务、设备台账）批量获取
// 请求方无法自行提供的评估属性。
//
// 实现要求：
//   - 并发安全：同一 Provider 会被多个评估并发调用；
//   - 尊重 ctx：整体评估时间预算通过 ctx 传入，超时/取消应尽快返回错误；
//   - 每次调用独立返回当次真实状态，不得在内部缓存会过期的结论
//     （引擎侧也不会缓存依赖失败的决策）。
//
// 返回的 map 应包含 attrs 中全部请求的属性；任一属性缺失或返回 error，
// 本次评估即按 ReasonDependencyUnavailable 降级拒绝。
type AttributeProvider interface {
	Fetch(ctx context.Context, req Request, attrs []string) (map[string]any, error)
}

// AttributeProviderFunc 是 AttributeProvider 的函数适配器，便于测试与简单接入。
type AttributeProviderFunc func(ctx context.Context, req Request, attrs []string) (map[string]any, error)

// Fetch 实现 AttributeProvider。
func (f AttributeProviderFunc) Fetch(ctx context.Context, req Request, attrs []string) (map[string]any, error) {
	return f(ctx, req, attrs)
}
