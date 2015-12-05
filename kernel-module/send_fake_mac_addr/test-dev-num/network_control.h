#ifndef MY_URL_REDIRECT_HEAD
#define MY_URL_REDIRECT_HEAD

struct gbuffer{ 
    u8  *buf; 
    u32 len; 
}; 
    
typedef struct gbuffer gbuffer; 
typedef struct gbuffer gbuffer_t;

static inline void gbuffer_init(gbuffer *p) { 
    p->len = 0; 
    p->buf = NULL; 
} 
   
static inline void __gbuffer_init(gbuffer *p, u8 *buf, u32 len) { 
    p->len = len; 
    p->buf = buf; 
} 
 
static inline int gbuffer_empty(gbuffer *p) { 
    return (p->buf == NULL); 
} 
 
static inline void gbuffer_free(gbuffer *p) { 
    if (NULL == p){ 
        return; 
	}

    if (likely(p->buf != NULL)){ 
        kfree( p->buf ); 
        p->buf = NULL; 
    } 
    p->len = 0; 
} 
 
static inline void _gbuffer_free(gbuffer *p)  { 
    if (NULL == p) {
        return; 
	}

    if (likely(p->buf != NULL)){ 
        kfree( p->buf ); 
        p->buf = NULL; 
    } 
    kfree(p); 
} 
 
static inline gbuffer_t* __gbuffer_alloc(void) { 
    gbuffer_t *p = NULL; 
    p = kzalloc(sizeof(*p), GFP_ATOMIC); 
    if (unlikely( NULL == p)){ 
        return NULL; 
    } 
 
    p->buf = NULL; 
    p->len = 0; 
    return p; 
} 
 
static inline gbuffer_t* _gbuffer_alloc(u32 len) { 
    gbuffer_t *p = NULL; 
    p = kzalloc(sizeof(*p), GFP_ATOMIC); 
    if (unlikely( NULL == p)) { 
        return NULL; 
    } 
    p->buf = kzalloc(len, GFP_ATOMIC); 
    if (unlikely(NULL == p->buf)){ 
        kfree( p ); 
        return NULL; 
    } 
 
    p->len = len; 
    return p; 
} 
 
static inline int gbuffer_alloc (gbuffer *p, u32 len) { 
    if ( NULL == p ) 
        return -1; 
    p->buf = kzalloc(len, GFP_ATOMIC); 
    if (unlikely( NULL == p->buf)) { 
        return -1; 
    } 
    p->len = len; 
    return 0; 
}

#endif // MY_URL_REDIRECT_HEAD
