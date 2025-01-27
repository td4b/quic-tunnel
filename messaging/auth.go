package messaging

// for now auth is simple, we will look into more strict auth later
func CheckApiKey(clientkey string, serverkey string) bool {
	return (clientkey == serverkey)
}
