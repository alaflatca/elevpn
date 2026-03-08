package client

type Client struct {
}

type ClientConfig struct {
}

func New(cfg ClientConfig) (*Client, error) {
	return &Client{}, nil
}

func (s *Client) Run() error {

	return nil
}
