package server

type Server struct {
}

type ServerConfig struct {
}

func New(cfg ServerConfig) (*Server, error) {
	return &Server{}, nil
}

func (s *Server) Run() error {

	return nil
}
