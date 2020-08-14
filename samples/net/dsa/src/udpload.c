#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <sys_clock.h>
#include <net/socket.h>
#include <posix/unistd.h>
#include <errno.h>

#include <logging/log.h>


// Loglevel of main function
LOG_MODULE_REGISTER(udpload, LOG_LEVEL_DBG);


//Setup and start udpload
#define UDPLOAD_STACK_SIZE 2048
#define UDPLOAD_PRIORITY      5 /* >0 is preemptable */

static void udpload_thread(void* t1, void* t2, void* t3);
K_THREAD_DEFINE(udpload_tid, UDPLOAD_STACK_SIZE,
                udpload_thread, NULL, NULL, NULL,
                UDPLOAD_PRIORITY, 0, 6000);

#define UDP_PORT 4888 

#define MAX_BUFFERSIZE 4000

#define GENERR 1
#define SUCCESS 0

#define ETH_HDR_LEN 14
#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define PKT_HDR_LEN (ETH_HDR_LEN + IP_HDR_LEN + UDP_HDR_LEN)

#define MAX_CLIENTS 8

#define RANDOM_DATA_PATTERN

typedef struct {
   uint32_t      s_addr;    /* source address */
   unsigned int  exp_seq;   /* next expected seq */
   unsigned int  rx_total;  /* total rx packets */
   unsigned int  tx_error;  /* total tx errors */
   unsigned int  seq_error; /* total tx errors */
   unsigned int  len_err;   /* total len errors */
   unsigned int  re_xmit;   /* Pkts re transmitted */
   unsigned int  pld_error; /* total bit errors in payload */
} ClientData;

unsigned long getMicroSeconds()
{
  return (unsigned long) k_uptime_get();
}

int isCliPrintEligible (unsigned int *prev_time)
{
  int retval = 1;
#if 0
  struct timespec ts;
  clock_gettime(CLOCK_REALTIME, &ts);
  if ((ts.tv_sec - *prev_time) < 60)
  {
    retval = 0;
  }
  *prev_time = ts.tv_sec;
#endif
  return retval;
}



// This function receives "requests" from multiple clients, replies them
// with the packet received and displays statistics.
int srv()
{
  struct sockaddr_in server_addr;
  struct sockaddr_in client_addr;
  socklen_t alen = sizeof(client_addr);

  int  sd = 0; 
  char *buf = 0;

  ClientData client[MAX_CLIENTS+1];

  int  retval  = 0;
  unsigned int  rx_seq  = 0; 
  unsigned int  rx_of   = 0;
  unsigned int  rx_src  = 0;
  unsigned int  rx_dest = 0;
  unsigned int  rx_error= 0;
  unsigned int  rx_len  = 0;
  unsigned int  i       = 0;
  unsigned int  t       = 0;
  unsigned int  rx_len_err = 0;
  unsigned int  bytes_rcvd = 0;
  unsigned int  prev_recv_err_ts = 0;
  unsigned int  prev_send_err_ts = 0;

#ifdef RANDOM_DATA_PATTERN
  LOG_INF("Server: use RANDOM DATA PATTERN");
#else
  LOG_INF("Server: use NULL DATA PATTERN");
#endif

  buf = (char *) malloc (MAX_BUFFERSIZE);
  if (0 == buf)
  {
    LOG_ERR("Server: Unable to allocate memory");
  }
 
  for (i=0; i <= MAX_CLIENTS; i++)
  {
    client[i].s_addr    = 0;
    client[i].exp_seq   = 1;
    client[i].rx_total  = 0;
    client[i].tx_error  = 0;
    client[i].seq_error = 0;
    client[i].len_err   = 0;
    client[i].re_xmit   = 0;
    client[i].pld_error = 0;
  }

  sd = socket (AF_INET, SOCK_DGRAM, IPPROTO_UDP);

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family   =  AF_INET;
  server_addr.sin_port = htons(UDP_PORT);
  server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

  retval = bind (sd, (struct sockaddr*)&server_addr,sizeof(server_addr));

  if (0 != retval) 
  {
    LOG_ERR("Server: Failed to bind port name");
  }

  while (1) 
  {
    memset(buf, 0, MAX_BUFFERSIZE); 
    retval = recvfrom(sd,buf, MAX_BUFFERSIZE, 0, (struct sockaddr*)&client_addr, &alen);
    //LOG_INF("Server: recvfrom len %d", retval);

    if (0 >= retval) 
    {
      if (1 == isCliPrintEligible(&prev_recv_err_ts))
        LOG_ERR("Server: Unexpected receive %d (%d)", retval, errno);
    }
    else
    {
      bytes_rcvd = retval + PKT_HDR_LEN;
      sscanf(buf, "UPi s=%d d=%d q=%d o=%d z=%d\n",
          &rx_src, &rx_dest, &rx_seq, &rx_of, &rx_len);
      rx_src = MAX_CLIENTS+1;
      for (int i=0; (i < MAX_CLIENTS) && (rx_src > MAX_CLIENTS); i++) {
        //LOG_INF("%d 0x%08x 0x%08x", i, client[i].s_addr, client_addr.sin_addr.s_addr);
        if (client[i].s_addr == client_addr.sin_addr.s_addr) {
          //char ipaddr[INET_ADDRSTRLEN];
          //inet_ntop(AF_INET, &(client_addr.sin_addr), ipaddr, INET_ADDRSTRLEN);
          //LOG_INF("Server: found addr %s for client %d", log_strdup(ipaddr), i);
          rx_src = i;
        } else if (client[i].s_addr == 0) {
          char ipaddr[INET_ADDRSTRLEN];
          inet_ntop(AF_INET, &(client_addr.sin_addr), ipaddr, INET_ADDRSTRLEN);
          LOG_ERR("Server: register addr %s for client %d",  log_strdup(ipaddr), i);
          rx_src = i;
          client[i].s_addr = client_addr.sin_addr.s_addr;
        }
      }

      if ((rx_src <= MAX_CLIENTS) && (bytes_rcvd == rx_len))
      {
        if (rx_seq == 1)
        {
          client[rx_src].exp_seq = 1;
          client[rx_src].rx_total= 0;
          client[rx_src].tx_error= 0;
          client[rx_src].seq_error=0;
          client[rx_src].len_err = 0;
          client[rx_src].pld_error=0;
          LOG_INF("Server: Rx-Msg %10d of %10d from %2d size %5d(test started)",
              client[rx_src].rx_total, rx_of, rx_src, rx_len);
        }

        if (rx_seq == client[rx_src].exp_seq) 
        {  
          client[rx_src].exp_seq++;
          client[rx_src].rx_total++;
#ifdef RANDOM_DATA_PATTERN
          // check payload
          if (retval > (int)strlen(buf)) {
            for (t = strlen(buf)+1; (int)t < retval; t++) {
              if (buf[t] != (char)((t%2) ? t/2 : ~(t/2))) {
                client[rx_src].pld_error++;
                LOG_INF("Server: Rx-Msg %10d of %10d from %2d size %5d (bit error %d %d/%d)",
                client[rx_src].rx_total, rx_of, rx_src, rx_len, t, buf[t], (char)t);
              } 
            }
          }
#endif
          if ((rx_seq%10000)==0) 
          {
            LOG_INF("Server: Rx-Msg %10d of %10d from %2d size %5d"
                "(client-err: seq=%d tx=%d len=%d) (glob-err: rx=%d)",
                client[rx_src].rx_total, rx_of, rx_src, rx_len, 
                client[rx_src].seq_error, client[rx_src].tx_error,
                client[rx_src].len_err, rx_error);
          }

          if (rx_seq == rx_of) 
          {
            LOG_INF("Server: Rx-Msg %10d of %10d from %2d size %5d"
                "(client-err: seq=%d tx=%d len=%d) (glob-err: rx=%d) "
                "bit error=%d)",
                client[rx_src].rx_total, rx_of, rx_src, rx_len,
                client[rx_src].seq_error, client[rx_src].tx_error,
                client[rx_src].len_err, rx_error, client[rx_src].pld_error);

            /* send back remote with the last packet */
            sprintf(buf,"UPi s=%d d=%d q=%d o=%d z=%d e=%d\n", rx_src,
                    rx_dest, rx_seq, rx_of, rx_len, 
                    client[rx_src].seq_error + client[rx_src].tx_error +  
                    client[rx_src].len_err   + rx_error + client[rx_src].pld_error);

            client[rx_src].exp_seq = 1;
            client[rx_src].rx_total= 0;
            client[rx_src].tx_error= 0;
            client[rx_src].seq_error= 0;
            client[rx_src].len_err= 0;
            client[rx_src].pld_error=0;
          }
          

          if (0 > sendto(sd, buf, (rx_len - PKT_HDR_LEN), 0,
                (struct sockaddr*)&client_addr,
                sizeof(client_addr)))
          {
            if (1 == isCliPrintEligible (&prev_send_err_ts))
              LOG_ERR("Server: Failed to send");
          }
          retval = 0;
        } else
        {
          LOG_ERR("Server: Wrong seq nbr %10d instead of %10d from %2d "
                      "size %5d (adjust seq) (client-err: seq=%d tx=%d len=%d)"
                      " (glob-err: rx=%d)",
                      rx_seq, client[rx_src].exp_seq, rx_src, rx_len,
                      client[rx_src].seq_error, client[rx_src].tx_error,
                      client[rx_src].len_err, rx_error);
          client[rx_src].exp_seq=rx_seq+1;
          client[rx_src].seq_error++;
        }
      } 
      else
      {
        if (bytes_rcvd != rx_len)
        {
          rx_len_err++;
          LOG_ERR("Server: Invalid message size received - Expected %d "
                       "Arrived %d", rx_len, bytes_rcvd);
        }
        if (rx_src > MAX_CLIENTS)
        {
          LOG_ERR("Server: Rx-Msg from unexpected source %2d",rx_src);
          rx_error++;
        }
      }
    }
  }
  free(buf);
  close (sd);
  return retval;
}

static void udpload_thread(void* t1, void* t2, void* t3) {
  LOG_INF("create UdpLoad");
  srv();
}
