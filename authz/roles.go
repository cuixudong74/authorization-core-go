package authz

// expandRoles 返回主体全部有效角色：直接角色沿继承关系向上展开，
// 取传递闭包。结果只取决于继承关系本身，与角色列表、
// 继承边的书写顺序无关；对循环继承安全（不会死循环）。
func expandRoles(direct []string, hierarchy map[string][]string) map[string]struct{} {
	effective := make(map[string]struct{}, len(direct))
	stack := make([]string, 0, len(direct))
	for _, r := range direct {
		if _, seen := effective[r]; !seen {
			effective[r] = struct{}{}
			stack = append(stack, r)
		}
	}
	for len(stack) > 0 {
		r := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		for _, parent := range hierarchy[r] {
			if _, seen := effective[parent]; !seen {
				effective[parent] = struct{}{}
				stack = append(stack, parent)
			}
		}
	}
	return effective
}
