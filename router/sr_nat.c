
#include <signal.h>
#include <assert.h>
#include "sr_nat.h"
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "sr_if.h"
#include "sr_router.h"

int next_tcp_port = -1;
int next_icmp_port = -1;

int sr_nat_init(struct sr_nat *nat) { /* Initializes the nat */

  assert(nat);

  /* Acquire mutex lock */
  pthread_mutexattr_init(&(nat->attr));
  pthread_mutexattr_settype(&(nat->attr), PTHREAD_MUTEX_RECURSIVE);
  int success = pthread_mutex_init(&(nat->lock), &(nat->attr));

  /* Initialize timeout thread */

  pthread_attr_init(&(nat->thread_attr));
  pthread_attr_setdetachstate(&(nat->thread_attr), PTHREAD_CREATE_JOINABLE);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_attr_setscope(&(nat->thread_attr), PTHREAD_SCOPE_SYSTEM);
  pthread_create(&(nat->thread), &(nat->thread_attr), sr_nat_timeout, nat);

  /* CAREFUL MODIFYING CODE ABOVE THIS LINE! */

  /* Initialize any variables here */
  nat->mappings = NULL;
  nat->incoming = NULL;
  next_tcp_port = MIN_NAT_PORT;
  next_icmp_port = MIN_NAT_PORT;

  return success;
}


int sr_nat_destroy(struct sr_nat *nat) {  /* Destroys the nat (free memory) */

  pthread_mutex_lock(&(nat->lock));

  /* free nat memory here */
  struct sr_nat_mapping *mapping = nat->mappings;
  while(mapping) {
    struct sr_nat_mapping *prev_mapping = mapping;
    mapping = mapping->next;
    free(prev_mapping);
  }

  struct sr_nat_tcp_syn *incoming = nat->incoming;
  while(incoming){
    struct sr_nat_tcp_syn *prev_incoming = incoming;
    incoming = incoming->next;
    free(prev_incoming);
  }

  pthread_kill(nat->thread, SIGKILL);
  return pthread_mutex_destroy(&(nat->lock)) &&
    pthread_mutexattr_destroy(&(nat->attr));

}

void *sr_nat_timeout(void *nat_ptr) {  /* Periodic Timeout handling */
  struct sr_nat *nat = (struct sr_nat *)nat_ptr;
  while (1) {
    sleep(1.0);
    pthread_mutex_lock(&(nat->lock));

    time_t curtime = time(NULL);

    /* Handle incoming SYNs */
    struct sr_nat_tcp_syn *prev_incoming = NULL;
    struct sr_nat_tcp_syn *incoming = nat->incoming;
    while(incoming) {
      /* do not respond to unsolicited inbound SYN packet for at least seconds */
      if(difftime(curtime, incoming->last_received) > 6) {
        struct sr_nat_mapping *mapping = sr_nat_lookup_external(nat, incoming->port, nat_mapping_tcp);
        if(!mapping) {
          send_icmp_msg(nat->sr, incoming->packet, incoming->len, icmp_type_dest_unreachable, icmp_dest_unreachable_port);
        }

        /* removing from list */
        if(prev_incoming) {
          prev_incoming->next = incoming->next;
        } else {
          nat->incoming = incoming->next;
        }

        free(incoming->packet);
        free(incoming);
      } else {
        prev_incoming = incoming;
        incoming = incoming->next;
      }
    }
    /* handle periodic tasks here */
    struct sr_nat_mapping *prev_mapping = NULL;
    struct sr_nat_mapping *mapping = nat->mappings;
    while(mapping) {
      if(mapping->type == nat_mapping_icmp) {
        if(difftime(curtime, mapping->last_updated) > nat->icmp_query_timeout) {
          sr_nat_remove_mapping(nat, mapping, prev_mapping);
        }
      } else if(mapping->type == nat_mapping_tcp) {
        bool remove_mapping = true;
        struct sr_nat_connection *prev_conn = NULL;
        struct sr_nat_connection *conn = mapping->conns;
        while(conn) {
          switch(conn->state) {
            case tcp_state_established:
            case tcp_state_fin_wait_1:
            case tcp_state_fin_wait_2:
            case tcp_state_close_wait:
            {
              if(difftime(curtime, conn->last_updated) > nat->tcp_established_idle_timeout) {
                sr_nat_remove_conn(nat, mapping, conn, prev_conn);
              } else {
                remove_mapping = false;
              }
              break;
            }

            case tcp_state_syn_sent:
            case tcp_state_syn_received:
            case tcp_state_last_ack:
            case tcp_state_closing:
            {
              if(difftime(curtime, conn->last_updated) > nat->tcp_transitory_idle_timeout) {
                sr_nat_remove_conn(nat, mapping, conn, prev_conn);
              } else {
                remove_mapping = false;
              }
              break;
            }

            default: {
              break;
            }
          }

          prev_conn = conn;
          conn = conn->next;
        }
        
        if(remove_mapping) {
          sr_nat_remove_mapping(nat, mapping, prev_mapping);
        }
      }

      prev_mapping = mapping;
      mapping = mapping->next;
    }

    pthread_mutex_unlock(&(nat->lock));
  }
  return NULL;
}

/* Get the mapping associated with given external port.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_external(struct sr_nat *nat,
    uint16_t aux_ext, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = nat->mappings;

  while(mapping) {
    if(mapping->aux_ext == aux_ext && mapping->type == type) {
      copy = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
      break;
    }
    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Get the mapping associated with given internal (ip, port) pair.
   You must free the returned structure if it is not NULL. */
struct sr_nat_mapping *sr_nat_lookup_internal(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle lookup here, malloc and assign to copy. */
  struct sr_nat_mapping *copy = NULL;
  struct sr_nat_mapping *mapping = nat->mappings;

  while(mapping) {
    if(mapping->ip_int == ip_int && mapping->aux_int == aux_int && mapping->type == type) {
      copy = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
      memcpy(copy, mapping, sizeof(struct sr_nat_mapping));
      break;
    }
    mapping = mapping->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Insert a new mapping into the nat's mapping table.
   Actually returns a copy to the new mapping, for thread safety.
 */
struct sr_nat_mapping *sr_nat_insert_mapping(struct sr_nat *nat,
  uint32_t ip_int, uint16_t aux_int, sr_nat_mapping_type type ) {

  pthread_mutex_lock(&(nat->lock));

  /* handle insert here, create a mapping, and then return a copy of it */
  struct sr_nat_mapping *mapping = NULL;
  mapping = sr_nat_lookup_internal(nat, ip_int, aux_int, type);
  if(mapping) {
    return mapping;
  }
  mapping = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping));
  
  mapping->type = type;
  mapping->ip_int = ip_int;
  mapping->ip_ext = 0;
  mapping->aux_int = aux_int;
  mapping->last_updated = time(NULL);
  mapping->conns = NULL;

  if(type == nat_mapping_icmp) {
    mapping->aux_ext = next_icmp_port++;
    if(next_icmp_port >= MAX_NAT_PORT) {
      next_icmp_port = MIN_NAT_PORT;
    }
  } else if(type == nat_mapping_tcp) {
    mapping->aux_ext = next_tcp_port++;
    if(next_tcp_port >= MAX_NAT_PORT) {
      next_tcp_port = MIN_NAT_PORT;
    }
  }

  mapping->next = nat->mappings;
  nat->mappings = mapping;

  struct sr_nat_mapping *copy = (struct sr_nat_mapping*)malloc(sizeof(struct sr_nat_mapping))  
  memcpy(copy, mapping, sizeof(struct sr_nat_mapping));

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Custom: remove a mapping from the nat's mapping table */
void sr_nat_remove_mapping(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_mapping *prev_mapping) {
  
  pthread_mutex_lock(&(nat->lock));

  if(!prev_mapping) {
    nat->mapping = mapping->next;
  } else {
    prev_mapping->next = mapping->next;
  }

  struct sr_nat_connection *conn = mapping->conns;
  while(conn) {
    free(conn);
    conn = conn->next;
  }
  free(mapping);

  pthread_mutex_unlock(&(nat->lock));
}

/* Custom: get a connection from the mapping's connection table */
struct sr_nat_connection *sr_nat_get_conn(struct sr_nat_mapping *mapping, uint32_t ip) {
  
  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_connection *copy = NULL;
  struct sr_nat_connection *conn = mapping->conns;

  while(conn) {
    if(conn->ip == ip) {
      copy = (struct sr_nat_connection*)malloc(sizeof(struct sr_nat_connection));
      memcpy(copy, conn, sizeof(struct sr_nat_connection));
      break;
    }
    conn = conn->next;
  }

  pthread_mutex_unlock(&(nat->lock));
  return copy;
}

/* Custom: insert a connection to the mapping's connection table */
struct sr_nat_connection *sr_nat_add_conn(struct sr_nat_mapping *mapping, uint32_t ip) {
  
  pthread_mutex_lock(&(nat->lock));

  struct sr_nat_connection *conn = (struct sr_nat_connection*)malloc(sizeof(struct sr_nat_connection));
  memset(conn, 0, sizeof(struct sr_nat_connection));

  conn->ip = ip;
  conn->state = tcp_state_closed;
  conn->last_updated = time(NULL);

  conn->next = mapping->conns;
  mapping->conns = conn;

  pthread_mutex_unlock(&(nat->lock));
  return conn;
}

/* Custom: remove a connection from the mapping's connection table */
void sr_nat_remove_conn(struct sr_nat *nat, struct sr_nat_mapping *mapping, struct sr_nat_connection *conn, struct sr_nat_connection *prev_conn) {
  
  pthread_mutex_lock(&(nat->lock));
  
  if(!prev_conn) {
    mapping->conns = conn->next;
  } else {
    prev_conn->next = conn->next;
  }

  free(conn);

  pthread_mutex_unlock(&(nat->lock));
}

/* Custom: add the incoming TCP SYN connection if it is not already existed */
void add_incoming_syn(struct sr_nat *nat, uint32_t src_ip, uint16_t src_port, uint8_t *packet, unsigned int len) {
  struct sr_nat_tcp_syn *incoming = nat->incoming;
  while(incoming) {
    if((incoming->ip == src_ip) && (incoming->port == src_port)) {
      return;
    }
    incoming = incoming->next;
  }

  incoming = (struct sr_nat_tcp_syn*)malloc(sizeof(struct sr_nat_tcp_syn));

  incoming->ip = src_ip;
  incoming->port = src_port;
  incoming->packet = (uint8_t*)malloc(len);
  memcpy(incoming->packet, packet, len);
  incoming->len = len;
  incoming->last_received = time(NULL);

  incoming->next = nat->incoming;
  nat->incoming = incoming;
}