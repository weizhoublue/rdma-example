/*
 * An example RDMA client side code. 
 * Author: Animesh Trivedi 
 *         atrivedi@apache.org
 */

#include "rdma_common.h"

/* These are basic RDMA resources */
/* These are RDMA connection related resources */
static struct rdma_event_channel *cm_event_channel = NULL;
static struct rdma_cm_id *cm_client_id = NULL;
static struct ibv_pd *pd = NULL;
static struct ibv_comp_channel *io_completion_channel = NULL;
static struct ibv_cq *client_cq = NULL;
static struct ibv_qp_init_attr qp_init_attr;
static struct ibv_qp *client_qp;
/* These are memory buffers related resources */
static struct ibv_mr *client_metadata_mr = NULL, 
		     *client_src_mr = NULL, 
		     *client_dst_mr = NULL, 
		     *server_metadata_mr = NULL;
static struct rdma_buffer_attr client_metadata_attr, server_metadata_attr;
static struct ibv_send_wr client_send_wr, *bad_client_send_wr = NULL;
static struct ibv_recv_wr server_recv_wr, *bad_server_recv_wr = NULL;
static struct ibv_sge client_send_sge, server_recv_sge;
/* Source and Destination buffers, where RDMA operations source and sink */
static char *src = NULL, *dst = NULL; 

/* This is our testing function */
static int check_src_dst() 
{
	return memcmp((void*) src, (void*) dst, strlen(src));
}

/* This function prepares client side connection resources for an RDMA connection */
static int client_prepare_connection(struct sockaddr_in *s_addr)
{
	struct rdma_cm_event *cm_event = NULL;
	int ret = -1;
	/*  创建一个 RDMA 事件通道 , 异步 RDMA 事件的机制  .    cm_event_channel 这个变量将是 一个重要的变量
	Open a channel used to report asynchronous communication event */
	/*
	   struct rdma_event_channel {
       	int			fd;
       };
	*/
	cm_event_channel = rdma_create_event_channel();
	if (!cm_event_channel) {
		rdma_error("Creating cm event channel failed, errno: %d \n", -errno);
		return -errno;
	}
	debug("RDMA CM event channel is created at : %p \n", cm_event_channel);
	/* rdma_cm_id is the connection identifier (like socket) which is used 
	 * to define an RDMA connection.
	 */
	/*  cm_client_id 将会包含有关 RDMA 连接的信息，例如连接类型、服务 ID 和端口号
        int rdma_create_id(struct rdma_event_channel *channel,
                   struct rdma_cm_id **id, void *context,
                   enum rdma_port_space ps)
	*/
	/* RDMA_PS_TCP 使用 TCP
	        enum rdma_port_space {
            	RDMA_PS_IPOIB = 0x0002,
            	RDMA_PS_TCP   = 0x0106,
            	RDMA_PS_UDP   = 0x0111,
            	RDMA_PS_IB    = 0x013F,
            };
	*/
		/*
    	   重要结构体 struct rdma_cm_id : https://elixir.bootlin.com/linux/latest/source/include/rdma/rdma_cm.h#L112
    	*/
	ret = rdma_create_id(cm_event_channel, &cm_client_id, 
			NULL,
			RDMA_PS_TCP);
	if (ret) {
		rdma_error("Creating cm id failed with errno: %d \n", -errno); 
		return -errno;
	}
	/* Resolve destination and optional source addresses from IP addresses  to
	 * an RDMA address.  If successful, the specified rdma_cm_id will be bound
	 * to a local device. */
	/*   将双方的 RDMA 地址 存储到  存储到  cm_client_id
	     将 server 的  IP 地址 转换为 RDMA 地址
	     生成本地使用的地址 , 如果不指定，使用路由进行计算
	                     If no source address is given, and the rdma_cm_id has not yet been bound to a device,
                         then the rdma_cm_id will be bound to a source address based on the
                        local routing tables
	     int rdma_resolve_addr(struct rdma_cm_id *id, struct sockaddr *src_addr,
         		      struct sockaddr *dst_addr, int timeout_ms);
	*/
	ret = rdma_resolve_addr(cm_client_id, NULL, (struct sockaddr*) s_addr, 2000);
	if (ret) {
		rdma_error("Failed to resolve address, errno: %d \n", -errno);
		return -errno;
	}
	debug("waiting for cm event: RDMA_CM_EVENT_ADDR_RESOLVED\n");
	/* 期待 RDMA_CM_EVENT_ADDR_RESOLVED 事件完成 */
	ret  = process_rdma_cm_event(cm_event_channel, 
			RDMA_CM_EVENT_ADDR_RESOLVED,
			&cm_event);
	if (ret) {
		rdma_error("Failed to receive a valid event, ret = %d \n", ret);
		return ret;
	}
	/* we ack the event */
	/* rdma_ack_cm_event 释放上一步函数中的 rdma_get_cm_event 的事件
	    All events which are allocated by rdma_get_cm_event must be released,
	*/
	ret = rdma_ack_cm_event(cm_event);
	if (ret) {
		rdma_error("Failed to acknowledge the CM event, errno: %d\n", -errno);
		return -errno;
	}
	debug("RDMA address is resolved \n");

	 /* Resolves an RDMA route to the destination address in order to 
	  * establish a connection */
	/* 解析 RDMA 连接的路由
	   int rdma_resolve_route(struct rdma_cm_id *id, int timeout_ms);
	*/
	ret = rdma_resolve_route(cm_client_id, 2000);
	if (ret) {
		rdma_error("Failed to resolve route, erno: %d \n", -errno);
	       return -errno;
	}
	debug("waiting for cm event: RDMA_CM_EVENT_ROUTE_RESOLVED\n");
	ret = process_rdma_cm_event(cm_event_channel, 
			RDMA_CM_EVENT_ROUTE_RESOLVED,
			&cm_event);
	if (ret) {
		rdma_error("Failed to receive a valid event, ret = %d \n", ret);
		return ret;
	}
	/* we ack the event */
	ret = rdma_ack_cm_event(cm_event);
	if (ret) {
		rdma_error("Failed to acknowledge the CM event, errno: %d \n", -errno);
		return -errno;
	}
	printf("Trying to connect to server at : %s port: %d \n", 
			inet_ntoa(s_addr->sin_addr),
			ntohs(s_addr->sin_port));
	/*       Allocate a protection domain
	 * Protection Domain (PD) is similar to a "process abstraction"
	 * in the operating system. All resources are tied to a particular PD. 
	 * And accessing recourses across PD will result in a protection fault.
	 */
	pd = ibv_alloc_pd(cm_client_id->verbs);
	if (!pd) {
		rdma_error("Failed to alloc pd, errno: %d \n", -errno);
		return -errno;
	}
	debug("pd allocated at %p \n", pd);
	/*   创建 completion channel ，实现 异步IO 的事件 通知 . 完成队列 (CQ) 是用于存储 RDMA 请求完成事件的队列
	 * Now we need a completion channel, were the I/O completion
	 * notifications are sent. Remember, this is different from connection 
	 * management (CM) event notifications. 
	 * A completion channel is also tied to an RDMA device, hence we will 
	 * use cm_client_id->verbs. 
	 */
	io_completion_channel = ibv_create_comp_channel(cm_client_id->verbs);
	if (!io_completion_channel) {
		rdma_error("Failed to create IO completion event channel, errno: %d\n",
			       -errno);
	return -errno;
	}
	debug("completion event channel created at : %p \n", io_completion_channel);
	/* Now we create a completion queue (CQ) where actual I/O 
	 * completion metadata is placed. The metadata is packed into a structure 
	 * called struct ibv_wc (wc = work completion). ibv_wc has detailed 
	 * information about the work completion. An I/O request in RDMA world 
	 * is called "work" ;) 
	 */
	client_cq = ibv_create_cq(cm_client_id->verbs /* which device*/, 
			CQ_CAPACITY /* maximum capacity*/, 
			NULL /* user context, not used here */,
			io_completion_channel /* which IO completion channel */, 
			0 /* signaling vector, not used here*/);
	if (!client_cq) {
		rdma_error("Failed to create CQ, errno: %d \n", -errno);
		return -errno;
	}
	debug("CQ created at %p with %d elements \n", client_cq, client_cq->cqe);

	/**  ibv_req_notify_cq 在 CQ 上开启后续所有事件的通知 。 函数会在 CQ 上放置一个完成队列条目 (CQE)，以指示应用程序已准备好接收有关特定类型完成事件的通知
     * ibv_req_notify_cq - Request completion notification on a CQ.  An
     *   event will be added to the completion channel associated with the
     *   CQ when an entry is added to the CQ.
     * @cq: The completion queue to request notification for.
     * @solicited_only: If non-zero, an event will be generated only for
     *   the next solicited CQ entry.  If zero, any CQ entry, solicited or
     *   not, will generate an event.
     */
	ret = ibv_req_notify_cq(client_cq, 0);
	if (ret) {
		rdma_error("Failed to request notifications, errno: %d\n", -errno);
		return -errno;
	}

	/*  创建 rdma_create_qp ， 包含了一队 (send, recv) queues 用于收和发 数据

	*/
       /* Now the last step, set up the queue pair (send, recv) queues and their capacity.
         * The capacity here is define statically but this can be probed from the 
	 * device. We just use a small number as defined in rdma_common.h */
       bzero(&qp_init_attr, sizeof qp_init_attr);
       qp_init_attr.cap.max_recv_sge = MAX_SGE; /* Maximum SGE per receive posting */
       qp_init_attr.cap.max_recv_wr = MAX_WR; /* Maximum receive posting capacity */
       qp_init_attr.cap.max_send_sge = MAX_SGE; /* Maximum SGE per send posting */
       qp_init_attr.cap.max_send_wr = MAX_WR; /* Maximum send posting capacity */
       qp_init_attr.qp_type = IBV_QPT_RC; /* QP type, RC = Reliable connection */
       /* We use same completion queue, but one can use different queues */
       qp_init_attr.recv_cq = client_cq; /* Where should I notify for receive completion operations */
       qp_init_attr.send_cq = client_cq; /* Where should I notify for send completion operations */
       /*Lets create a QP */
       ret = rdma_create_qp(cm_client_id /* which connection id */,
		       pd /* which protection domain*/,
		       &qp_init_attr /* Initial attributes */);
	if (ret) {
		rdma_error("Failed to create QP, errno: %d \n", -errno);
	       return -errno;
	}
	client_qp = cm_client_id->qp;
	debug("QP created at %p \n", client_qp);
	return 0;
}

/* 准备通信的 buffer ， Pre-posts a receive buffer before calling rdma_connect () */
static int client_pre_post_recv_buffer()
{
	int ret = -1;
	// Register a memory region
	server_metadata_mr = rdma_buffer_register(pd,
			&server_metadata_attr,
			sizeof(server_metadata_attr),
			(IBV_ACCESS_LOCAL_WRITE));
	if(!server_metadata_mr){
		rdma_error("Failed to setup the server metadata mr , -ENOMEM\n");
		return -ENOMEM;
	}
	// 本地的内存地址和长度
	server_recv_sge.addr = (uint64_t) server_metadata_mr->addr;
	server_recv_sge.length = (uint32_t) server_metadata_mr->length;
	server_recv_sge.lkey = (uint32_t) server_metadata_mr->lkey;

	/* now we link it to the request */
	bzero(&server_recv_wr, sizeof(server_recv_wr));
	server_recv_wr.sg_list = &server_recv_sge;
	server_recv_wr.num_sge = 1;

	// ibv_post_recv : Post a list of work requests to a receive queue.
	// 这个函数不涉及向对方发送信息，而只是 将接收请求 发布到 本地的接收队列 (RQ) 中。
	// 这样，后续 RDMA 异步接收数据时，就知道 把RDMA 数据 写入到 本地内存的位置
	ret = ibv_post_recv(client_qp /* which QP */,
		      &server_recv_wr /* receive work request*/,
		      &bad_server_recv_wr /* error WRs */);
	if (ret) {
		rdma_error("Failed to pre-post the receive buffer, errno: %d \n", ret);
		return ret;
	}
	debug("Receive buffer pre-posting is successful \n");
	return 0;
}

/* Connects to the RDMA server */
static int client_connect_to_server() 
{
	struct rdma_conn_param conn_param;
	struct rdma_cm_event *cm_event = NULL;
	int ret = -1;
	bzero(&conn_param, sizeof(conn_param));
	conn_param.initiator_depth = 3;
	conn_param.responder_resources = 3;
	conn_param.retry_count = 3; // if fail, then how many times to retry

	/*
        基于 cm 库进行 tcp 建联 ？
	*/
	// cm_client_id 中存储了对方和本地的各种 地址和队列等
	ret = rdma_connect(cm_client_id, &conn_param);
	if (ret) {
		rdma_error("Failed to connect to remote host , errno: %d\n", -errno);
		return -errno;
	}
	debug("waiting for cm event: RDMA_CM_EVENT_ESTABLISHED\n");
	// 等待事件 RDMA_CM_EVENT_ESTABLISHED 完成
	ret = process_rdma_cm_event(cm_event_channel, 
			RDMA_CM_EVENT_ESTABLISHED,
			&cm_event);
	if (ret) {
		rdma_error("Failed to get cm event, ret = %d \n", ret);
	       return ret;
	}
	// 释放事件
	ret = rdma_ack_cm_event(cm_event);
	if (ret) {
		rdma_error("Failed to acknowledge cm event, errno: %d\n", 
			       -errno);
		return -errno;
	}
	printf("The client is connected successfully \n");
	return 0;
}

/* Exchange buffer metadata with the server. The client sends its, and then receives
 * from the server. The client-side metadata on the server is _not_ used because
 * this program is client driven. But it shown here how to do it for the illustration
 * purposes
 */
static int client_xchange_metadata_with_server()
{
	struct ibv_wc wc[2];
	int ret = -1;
	// src 是我们命令行中要传递的 数据
	client_src_mr = rdma_buffer_register(pd,
			src,
			strlen(src),
			(IBV_ACCESS_LOCAL_WRITE|
			 IBV_ACCESS_REMOTE_READ|
			 IBV_ACCESS_REMOTE_WRITE));
	if(!client_src_mr){
		rdma_error("Failed to register the first buffer, ret = %d \n", ret);
		return ret;
	}
	/* we prepare metadata for the first buffer */
	client_metadata_attr.address = (uint64_t) client_src_mr->addr; 
	client_metadata_attr.length = client_src_mr->length; 
	client_metadata_attr.stag.local_stag = client_src_mr->lkey;
	/* now we register the metadata memory */
	client_metadata_mr = rdma_buffer_register(pd,
			&client_metadata_attr,
			sizeof(client_metadata_attr),
			IBV_ACCESS_LOCAL_WRITE);
	if(!client_metadata_mr) {
		rdma_error("Failed to register the client metadata buffer, ret = %d \n", ret);
		return ret;
	}
	/* now we fill up SGE */
	client_send_sge.addr = (uint64_t) client_metadata_mr->addr;
	client_send_sge.length = (uint32_t) client_metadata_mr->length;
	client_send_sge.lkey = client_metadata_mr->lkey;
	/* now we link to the send work request */
	bzero(&client_send_wr, sizeof(client_send_wr));
	client_send_wr.sg_list = &client_send_sge;
	client_send_wr.num_sge = 1;
	client_send_wr.opcode = IBV_WR_SEND; // !!!!!!!!!!!!!!! 发送数据 操作码
	client_send_wr.send_flags = IBV_SEND_SIGNALED;
	/* Now we post it */
	// 发送给对方
	ret = ibv_post_send(client_qp, 
		       &client_send_wr,
	       &bad_client_send_wr);
	if (ret) {
		rdma_error("Failed to send client metadata, errno: %d \n", 
				-errno);
		return -errno;
	}
	/* at this point we are expecting 2 work completion. One for our 
	 * send and one for recv that we will get from the server for 
	 * its buffer information */
	ret = process_work_completion_events(io_completion_channel, 
			wc, 2);
	if(ret != 2) {
		rdma_error("We failed to get 2 work completions , ret = %d \n",
				ret);
		return ret;
	}
	debug("Server sent us its buffer location and credentials, showing \n");
	show_rdma_buffer_attr(&server_metadata_attr);
	return 0;
}

/* This function does :
 * 1) Prepare memory buffers for RDMA operations 
 * 1) RDMA write from src -> remote buffer 
 * 2) RDMA read from remote bufer -> dst
 */ 
static int client_remote_memory_ops() 
{
    // ------------ IBV_WR_RDMA_WRITE  直接向对方 内存中写入 业务数据， 无需对方应用的参与
	struct ibv_wc wc;
	int ret = -1;
	client_dst_mr = rdma_buffer_register(pd,
			dst,
			strlen(src),
			(IBV_ACCESS_LOCAL_WRITE | 
			 IBV_ACCESS_REMOTE_WRITE | 
			 IBV_ACCESS_REMOTE_READ));
	if (!client_dst_mr) {
		rdma_error("We failed to create the destination buffer, -ENOMEM\n");
		return -ENOMEM;
	}
	/* Step 1: is to copy the local buffer into the remote buffer. We will 
	 * reuse the previous variables. */
	/* now we fill up SGE */
	client_send_sge.addr = (uint64_t) client_src_mr->addr;
	client_send_sge.length = (uint32_t) client_src_mr->length;
	client_send_sge.lkey = client_src_mr->lkey;
	/* now we link to the send work request */
	bzero(&client_send_wr, sizeof(client_send_wr));
	client_send_wr.sg_list = &client_send_sge;
	client_send_wr.num_sge = 1;
	client_send_wr.opcode = IBV_WR_RDMA_WRITE;  // 进行 write 操作，把 业务数据直接 写入对方 内存中， 无需对方应用的参与
	client_send_wr.send_flags = IBV_SEND_SIGNALED;
	/* we have to tell server side info for RDMA */
	client_send_wr.wr.rdma.rkey = server_metadata_attr.stag.remote_stag;
	client_send_wr.wr.rdma.remote_addr = server_metadata_attr.address;
	/* Now we post it */
	// 发送 业务数据 给本地队列， 随后 会被异步的 转发给 对方，等待 事件通知
	ret = ibv_post_send(client_qp, 
		       &client_send_wr,
	       &bad_client_send_wr);
	if (ret) {
		rdma_error("Failed to write client src buffer, errno: %d \n", 
				-errno);
		return -errno;
	}
	/* at this point we are expecting 1 work completion for the write */
	ret = process_work_completion_events(io_completion_channel, 
			&wc, 1);
	if(ret != 1) {
		rdma_error("We failed to get 1 work completions , ret = %d \n",
				ret);
		return ret;
	}
	debug("Client side WRITE is complete \n");

	// ------------ IBV_WR_RDMA_READ   主动 从对方内存中  读取 业务数据 ， 无需对方应用的参与
	/* Now we prepare a READ using same variables but for destination */
	client_send_sge.addr = (uint64_t) client_dst_mr->addr;
	client_send_sge.length = (uint32_t) client_dst_mr->length;
	client_send_sge.lkey = client_dst_mr->lkey;
	/* now we link to the send work request */
	bzero(&client_send_wr, sizeof(client_send_wr));
	client_send_wr.sg_list = &client_send_sge;
	client_send_wr.num_sge = 1;
	client_send_wr.opcode = IBV_WR_RDMA_READ;  // 进行 read 操作，把 业务数据直接 写入对方 内存中 ， 无需对方应用的参与
	client_send_wr.send_flags = IBV_SEND_SIGNALED;
	/* we have to tell server side info for RDMA */
	client_send_wr.wr.rdma.rkey = server_metadata_attr.stag.remote_stag;
	client_send_wr.wr.rdma.remote_addr = server_metadata_attr.address;
	/* Now we post it */
	ret = ibv_post_send(client_qp, 
		       &client_send_wr,
	       &bad_client_send_wr);
	if (ret) {
		rdma_error("Failed to read client dst buffer from the master, errno: %d \n", 
				-errno);
		return -errno;
	}
	/* at this point we are expecting 1 work completion for the write */
	ret = process_work_completion_events(io_completion_channel, 
			&wc, 1);
	if(ret != 1) {
		rdma_error("We failed to get 1 work completions , ret = %d \n",
				ret);
		return ret;
	}
	debug("Client side READ is complete \n");
	return 0;
}

/* This function disconnects the RDMA connection from the server and cleans up 
 * all the resources.
 */
static int client_disconnect_and_clean()
{
	struct rdma_cm_event *cm_event = NULL;
	int ret = -1;
	/* active disconnect from the client side */
	ret = rdma_disconnect(cm_client_id);
	if (ret) {
		rdma_error("Failed to disconnect, errno: %d \n", -errno);
		//continuing anyways
	}
	ret = process_rdma_cm_event(cm_event_channel, 
			RDMA_CM_EVENT_DISCONNECTED,
			&cm_event);
	if (ret) {
		rdma_error("Failed to get RDMA_CM_EVENT_DISCONNECTED event, ret = %d\n",
				ret);
		//continuing anyways 
	}
	ret = rdma_ack_cm_event(cm_event);
	if (ret) {
		rdma_error("Failed to acknowledge cm event, errno: %d\n", 
			       -errno);
		//continuing anyways
	}
	/* Destroy QP */
	rdma_destroy_qp(cm_client_id);
	/* Destroy client cm id */
	ret = rdma_destroy_id(cm_client_id);
	if (ret) {
		rdma_error("Failed to destroy client id cleanly, %d \n", -errno);
		// we continue anyways;
	}
	/* Destroy CQ */
	ret = ibv_destroy_cq(client_cq);
	if (ret) {
		rdma_error("Failed to destroy completion queue cleanly, %d \n", -errno);
		// we continue anyways;
	}
	/* Destroy completion channel */
	ret = ibv_destroy_comp_channel(io_completion_channel);
	if (ret) {
		rdma_error("Failed to destroy completion channel cleanly, %d \n", -errno);
		// we continue anyways;
	}
	/* Destroy memory buffers */
	rdma_buffer_deregister(server_metadata_mr);
	rdma_buffer_deregister(client_metadata_mr);	
	rdma_buffer_deregister(client_src_mr);	
	rdma_buffer_deregister(client_dst_mr);	
	/* We free the buffers */
	free(src);
	free(dst);
	/* Destroy protection domain */
	ret = ibv_dealloc_pd(pd);
	if (ret) {
		rdma_error("Failed to destroy client protection domain cleanly, %d \n", -errno);
		// we continue anyways;
	}
	rdma_destroy_event_channel(cm_event_channel);
	printf("Client resource clean up is complete \n");
	return 0;
}

void usage() {
	printf("Usage:\n");
	printf("rdma_client: [-a <server_addr>] [-p <server_port>] -s string (required)\n");
	printf("(default IP is 127.0.0.1 and port is %d)\n", DEFAULT_RDMA_PORT);
	exit(1);
}

int main(int argc, char **argv) {
	struct sockaddr_in server_sockaddr;
	int ret, option;
	bzero(&server_sockaddr, sizeof server_sockaddr);
	server_sockaddr.sin_family = AF_INET;
	server_sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	/* buffers are NULL */
	src = dst = NULL; 
	/* Parse Command Line Arguments */
	while ((option = getopt(argc, argv, "s:a:p:")) != -1) {
		switch (option) {
			case 's':
				printf("Passed string is : %s , with count %u \n", 
						optarg, 
						(unsigned int) strlen(optarg));
				src = calloc(strlen(optarg) , 1);
				if (!src) {
					rdma_error("Failed to allocate memory : -ENOMEM\n");
					return -ENOMEM;
				}
				/* Copy the passes arguments */
				strncpy(src, optarg, strlen(optarg));
				dst = calloc(strlen(optarg), 1);
				if (!dst) {
					rdma_error("Failed to allocate destination memory, -ENOMEM\n");
					free(src);
					return -ENOMEM;
				}
				break;
			case 'a':
				/* remember, this overwrites the port info */
				ret = get_addr(optarg, (struct sockaddr*) &server_sockaddr);
				if (ret) {
					rdma_error("Invalid IP \n");
					return ret;
				}
				break;
			case 'p':
				/* passed port to listen on */
				server_sockaddr.sin_port = htons(strtol(optarg, NULL, 0)); 
				break;
			default:
				usage();
				break;
			}
		}
	if (!server_sockaddr.sin_port) {
	  /* no port provided, use the default port */
	  server_sockaddr.sin_port = htons(DEFAULT_RDMA_PORT);
	  }
	if (src == NULL) {
		printf("Please provide a string to copy \n");
		usage();
       	}
    // 准备各种 乱七八糟
	ret = client_prepare_connection(&server_sockaddr);
	if (ret) { 
		rdma_error("Failed to setup client connection , ret = %d \n", ret);
		return ret;
	 }
	 // 准备好本地的 接收缓存
	ret = client_pre_post_recv_buffer(); 
	if (ret) { 
		rdma_error("Failed to setup client connection , ret = %d \n", ret);
		return ret;
	}
	// 和对端 建立好链接
	ret = client_connect_to_server();
	if (ret) { 
		rdma_error("Failed to setup client connection , ret = %d \n", ret);
		return ret;
	}
	// 双方交换 一些基础信息
	ret = client_xchange_metadata_with_server();
	if (ret) {
		rdma_error("Failed to setup client connection , ret = %d \n", ret);
		return ret;
	}
	// 发送 业务数据 给对方  ， 然后向对方 索要读取 数据
	ret = client_remote_memory_ops();
	if (ret) {
		rdma_error("Failed to finish remote memory ops, ret = %d \n", ret);
		return ret;
	}

	// 比较我们发生过去的业务数据， 和 对方echo回来的业务数据 是否一直
	if (check_src_dst()) {
		rdma_error("src and dst buffers do not match \n");
	} else {
		printf("...\nSUCCESS, source and destination buffers match \n");
	}

    // client 主动关闭 链接
	ret = client_disconnect_and_clean();
	if (ret) {
		rdma_error("Failed to cleanly disconnect and clean up resources \n");
	}
	return ret;
}

