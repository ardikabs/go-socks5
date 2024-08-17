package slice

func In[T comparable](i T, items []T) bool {
	for _, item := range items {
		if item == i {
			return true
		}
	}

	return false
}
