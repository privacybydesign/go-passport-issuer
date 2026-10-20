module iris-verifier

go 1.26.0

require (
	github.com/gorilla/websocket v1.5.3
	github.com/redis/go-redis/v9 v9.21.0
	github.com/stretchr/testify v1.11.1
	go-passport-issuer v0.0.0
)

require (
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

// The recorder and the Redis Sentinel client are shared with the passport
// issuer, which lives in the same repository as module go-passport-issuer.
replace go-passport-issuer => ../backend
