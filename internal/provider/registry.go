package provider

type Registry struct {
	Providers []Provider
}

func NewRegistry(providers ...Provider) Registry {
	return Registry{Providers: providers}
}
