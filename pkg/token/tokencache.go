package token

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"gopkg.in/yaml.v2"
)

// env variable name for custom credential cache file location
const tokenCacheFileNameEnv = "AWS_IAM_AUTHENTICATOR_TOKEN_CACHE_FILE"

// tokenCache is a map of clusterID/roleARNs to cached credentials
type tokenCache struct {
	// a map of clusterIDs/profiles/roleARNs to cachedCredentials
	ClusterMap map[string]map[string]map[string]Token `yaml:"clusters"`
}

// TokenCacheKey contains all the keys needed to look up a token
type TokenCacheKey struct {
	ClusterID string
	Profile   string
	RoleARN   string
}

func NewTokenCache() (*tokenCache, error) {
	filename, ok := e.LookupEnv(tokenCacheFileNameEnv)
	if !ok {
		filename = filepath.Join(UserHomeDir(), ".kube", "cache", "aws-iam-authenticator", "tokens.yaml")
	}
	if err := f.MkdirAll(filepath.Dir(filename), 0700); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	if info, err := f.Stat(filename); !os.IsNotExist(err) {
		if info.Mode()&0077 != 0 {
			// cache file has secret credentials and should only be accessible to the user, refuse to use it.
			return nil, fmt.Errorf("cache file %s is not private", filename)
		}
	}
	lock := newFlock(filename)
	defer lock.Unlock()
	// wait up to a second for the file to lock
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()
	ok, err := lock.TryRLockContext(ctx, 250*time.Millisecond) // try to lock every 1/4 second
	if !ok {
		// unable to lock the cache, something is wrong, refuse to use it.
		return nil, fmt.Errorf("unable to read lock file %s: %v", filename, err)
	}
	cache, err := readTokenCache(filename)
	if err != nil {
		return nil, err
	}
	return cache, nil
}

func readTokenCache(filename string) (*tokenCache, error) {
	cache := &tokenCache{}
	cacheData, err := f.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("unable to read token cache file %s: %v", filename, err)
	}
	err = yaml.Unmarshal(cacheData, cache)
	if err != nil {
		return nil, fmt.Errorf("unable to unmarshal yaml for token cache %s: %v", filename, err)
	}
	if cache.ClusterMap == nil {
		cache.ClusterMap = make(map[string]map[string]map[string]Token)
	}
	return cache, nil
}

// WriteTokenCache writes the token cache back to the filesystem
func WriteTokenCache(cache *tokenCache) error {
	filename, ok := e.LookupEnv(tokenCacheFileNameEnv)
	if !ok {
		filename = filepath.Join(UserHomeDir(), ".kube", "cache", "aws-iam-authenticator", "tokens.yaml")
	}
	cacheData, err := yaml.Marshal(cache)
	if err != nil {
		return fmt.Errorf("unable to marshal token cache data %s: %v", filename, err)
	}
	lock := newFlock(filename)
	defer lock.Unlock()
	// wait up to a second for the file to lock
	ctx, cancel := context.WithTimeout(context.TODO(), time.Second)
	defer cancel()
	ok, err = lock.TryRLockContext(ctx, 250*time.Millisecond) // try to lock every 1/4 second
	if !ok {
		// unable to lock the cache, something is wrong, refuse to use it.
		return fmt.Errorf("unable to write lock file %s: %v", filename, err)
	}
	err = f.WriteFile(filename, cacheData, 0600)
	if err != nil {
		return fmt.Errorf("unable to write token cache file %s: %v", filename, err)
	}
	return nil
}

func (c *tokenCache) Get(key TokenCacheKey) (token Token, exists bool) {
	if _, ok := c.ClusterMap[key.ClusterID]; ok {
		if _, ok := c.ClusterMap[key.ClusterID][key.Profile]; ok {
			// we at least have this cluster and profile combo in the map, if no matching roleARN, map will
			// return the zero-value for cachedCredential, which expired a long time ago.
			token = c.ClusterMap[key.ClusterID][key.Profile][key.RoleARN]
			return token, true
		}
	}
	return token, false
}

func (c *tokenCache) Put(key TokenCacheKey, token Token) {
	if _, ok := c.ClusterMap[key.ClusterID]; !ok {
		// first use of this cluster id
		c.ClusterMap[key.ClusterID] = map[string]map[string]Token{}
	}
	if _, ok := c.ClusterMap[key.ClusterID][key.Profile]; !ok {
		// first use of this profile
		c.ClusterMap[key.ClusterID][key.Profile] = map[string]Token{}
	}
	c.ClusterMap[key.ClusterID][key.Profile][key.RoleARN] = token
}

// TokenIsExpired checks the token's Expiration
func TokenIsExpired(tok Token) bool {
	return (time.Until(tok.Expiration) < (1 * time.Minute))
}
