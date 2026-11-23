package relais

// Cache LRU en mémoire, borné, avec expiration par TTL. Aucune donnée n'est
// écrite sur disque et aucune requête n'est journalisée.

import (
	"container/list"
	"sync"
	"time"
)

type entree struct {
	cle    string
	msg    []byte
	stocke time.Time
	expire time.Time
}

type cache struct {
	mu         sync.Mutex
	max        int
	lru        *list.List
	elements   map[string]*list.Element
	maintenant func() time.Time
}

func nouveauCache(max int) *cache {
	if max < 1 {
		max = 1
	}
	return &cache{
		max:        max,
		lru:        list.New(),
		elements:   make(map[string]*list.Element, max),
		maintenant: time.Now,
	}
}

// obtenir renvoie la réponse et l'ancienneté de l'entrée. Une entrée expirée
// est retirée.
func (c *cache) obtenir(cle string) ([]byte, time.Duration, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	el, ok := c.elements[cle]
	if !ok {
		return nil, 0, false
	}
	e := el.Value.(*entree)
	maintenant := c.maintenant()
	if !maintenant.Before(e.expire) {
		c.lru.Remove(el)
		delete(c.elements, cle)
		return nil, 0, false
	}
	c.lru.MoveToFront(el)
	age := maintenant.Sub(e.stocke)
	if age < 0 {
		age = 0
	}
	return e.msg, age, true
}

// poser insère ou rafraîchit une entrée et évince la plus ancienne au-delà de
// la capacité.
func (c *cache) poser(cle string, msg []byte, ttl time.Duration) {
	if ttl <= 0 {
		return
	}
	copie := append([]byte(nil), msg...)
	maintenant := c.maintenant()
	c.mu.Lock()
	defer c.mu.Unlock()
	if el, ok := c.elements[cle]; ok {
		e := el.Value.(*entree)
		e.msg = copie
		e.stocke = maintenant
		e.expire = maintenant.Add(ttl)
		c.lru.MoveToFront(el)
		return
	}
	el := c.lru.PushFront(&entree{
		cle:    cle,
		msg:    copie,
		stocke: maintenant,
		expire: maintenant.Add(ttl),
	})
	c.elements[cle] = el
	for c.lru.Len() > c.max {
		dernier := c.lru.Back()
		if dernier == nil {
			break
		}
		c.lru.Remove(dernier)
		delete(c.elements, dernier.Value.(*entree).cle)
	}
}

func (c *cache) taille() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.lru.Len()
}
