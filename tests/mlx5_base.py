# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2020 NVIDIA Corporation . All rights reserved. See COPYING file

import unittest
import resource
import random
import struct
import errno
import math
import time
import sys

from pyverbs.providers.mlx5.mlx5dv import Mlx5Context, Mlx5DVContextAttr, \
    Mlx5DVQPInitAttr, Mlx5QP, Mlx5DVDCInitAttr, Mlx5DCIStreamInitAttr, \
    Mlx5DevxObj, Mlx5UMEM, Mlx5UAR, WqeDataSeg, WqeCtrlSeg, Wqe, Mlx5Cqe64, \
    Mlx5DVCQInitAttr, Mlx5CQ
from tests.base import RoCETrafficResources, set_rnr_attributes, DCT_KEY, \
    RDMATestCase, PyverbsAPITestCase, RDMACMBaseTest, BaseResources, PATH_MTU, \
    RNR_RETRY, RETRY_CNT, MIN_RNR_TIMER, TIMEOUT, MAX_RDMA_ATOMIC, RCResources, \
    is_gid_available
from pyverbs.pyverbs_error import PyverbsRDMAError, PyverbsUserError, \
    PyverbsError
from pyverbs.providers.mlx5.mlx5dv_objects import Mlx5DvObj
from pyverbs.qp import QPCap, QPInitAttrEx, QPAttr
from pyverbs.providers.mlx5.mlx5_enums import mlx5dv_qp_init_attr_mask, mlx5dv_dc_type, mlx5dv_qp_init_attr_mask, \
    mlx5dv_context_attr_flags, mlx5dv_obj_type, mlx5dv_context_attr_comp_mask, MLX5_SEND_WQE_BB, MLX5_SEND_WQE_SHIFT, \
    MLX5_WQE_CTRL_CQ_UPDATE, MLX5_OPCODE_SEND_IMM, MLX5_SND_DBR, MLX5_RCV_DBR, MLX5_CQE_INVALID, MLX5_CQE_RESP_ERR, \
    MLX5_CQE_REQ_ERR, MLX5_CQE_REQ, MLX5_CQE_RESP_SEND_IMM, _MLX5DV_UAR_ALLOC_TYPE_NC
from pyverbs.addr import AHAttr, GlobalRoute
from pyverbs.cq import CqInitAttrEx
from pyverbs.device import FdArr
import pyverbs.mem_alloc as mem
import pyverbs.dma_util as dma
import pyverbs.device as d
from pyverbs.pd import PD
from pyverbs.libibverbs_enums import ibv_qp_init_attr_mask, ibv_qp_type, ibv_qp_state, \
    ibv_access_flags, ibv_qp_attr_mask, ibv_wc_status, ibv_rereg_mr_flags, ibv_wr_opcode, \
    ibv_gid_type_sysfs, ibv_qp_create_send_ops_flags
from pyverbs.mr import MR
import tests.utils

MLX5_CQ_SET_CI = 0
POLL_CQ_TIMEOUT = 5  # In seconds
PORT_STATE_TIMEOUT = 20  # In seconds

MELLANOX_VENDOR_ID = 0x02c9
MLX5_DEVS = {
    0x1011,  # MT4113 Connect-IB
    0x1012,  # Connect-IB Virtual Function
    0x1013,  # ConnectX-4
    0x1014,  # ConnectX-4 Virtual Function
    0x1015,  # ConnectX-4LX
    0x1016,  # ConnectX-4LX Virtual Function
    0x1017,  # ConnectX-5, PCIe 3.0
    0x1018,  # ConnectX-5 Virtual Function
    0x1019,  # ConnectX-5 Ex
    0x101a,  # ConnectX-5 Ex VF
    0x101b,  # ConnectX-6
    0x101c,  # ConnectX-6 VF
    0x101d,  # ConnectX-6 DX
    0x101e,  # ConnectX family mlx5Gen Virtual Function
    0x101f,  # ConnectX-6 LX
    0x1021,  # ConnectX-7
    0x1023,  # ConnectX-8
    0xa2d2,  # BlueField integrated ConnectX-5 network controller
    0xa2d3,  # BlueField integrated ConnectX-5 network controller VF
    0xa2d6,  # BlueField-2 integrated ConnectX-6 Dx network controller
    0xa2dc,  # BlueField-3 integrated ConnectX-7 network controller
    0xa2df,  # BlueField-4 integrated ConnectX-8 network controller
}

DCI_TEST_GOOD_FLOW = 0
DCI_TEST_BAD_FLOW_WITH_RESET = 1
DCI_TEST_BAD_FLOW_WITHOUT_RESET = 2
IB_SMP_ATTR_PORT_INFO = 0x0015
IB_MGMT_CLASS_SUBN_LID_ROUTED = 0x01
IB_MGMT_METHOD_GET = 0x01
DB_BF_DBR_LESS_BUF_OFFSET = 0x600


class PortStatus:
    MLX5_PORT_UP = 1
    MLX5_PORT_DOWN = 2


class PortState:
    NO_STATE_CHANGE = 0
    DOWN = 1
    INIT = 2
    ARMED = 3
    ACTIVE = 4


def is_mlx5_dev(ctx):
    dev_attrs = ctx.query_device()
    return dev_attrs.vendor_id == MELLANOX_VENDOR_ID and \
        dev_attrs.vendor_part_id in MLX5_DEVS


def skip_if_not_mlx5_dev(ctx):
    if not is_mlx5_dev(ctx):
        raise unittest.SkipTest('Can not run the test over non MLX5 device')


class Mlx5PyverbsAPITestCase(PyverbsAPITestCase):
    def setUp(self):
        super().setUp()
        skip_if_not_mlx5_dev(self.ctx)


class Mlx5RDMATestCase(RDMATestCase):
    def setUp(self):
        super().setUp()
        skip_if_not_mlx5_dev(d.Context(name=self.dev_name))


class Mlx5RDMACMBaseTest(RDMACMBaseTest):
    def setUp(self):
        super().setUp()
        skip_if_not_mlx5_dev(d.Context(name=self.dev_name))


class Mlx5DcResources(RoCETrafficResources):
    def __init__(self, dev_name, ib_port, gid_index, send_ops_flags,
                 qp_count=1, create_flags=0):
        self.send_ops_flags = send_ops_flags
        self.create_flags = create_flags
        super().__init__(dev_name, ib_port, gid_index, with_srq=True,
                         qp_count=qp_count)

    def to_rts(self):
        attr = self.create_qp_attr()
        for i in range(self.qp_count):
            self.qps[i].to_rts(attr)
        self.dct_qp.to_rtr(attr)

    def create_context(self):
        mlx5dv_attr = Mlx5DVContextAttr()
        try:
            self.ctx = Mlx5Context(mlx5dv_attr, name=self.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening mlx5 context is not supported')

    def create_mr(self):
        access = ibv_access_flags.IBV_ACCESS_REMOTE_WRITE | ibv_access_flags.IBV_ACCESS_LOCAL_WRITE | \
                 ibv_access_flags.IBV_ACCESS_REMOTE_ATOMIC | ibv_access_flags.IBV_ACCESS_REMOTE_READ
        self.mr = MR(self.pd, self.msg_size, access)

    def create_qp_cap(self):
        return QPCap(100, 0, 1, 0)

    def create_qp_attr(self):
        qp_attr = QPAttr(port_num=self.ib_port)
        set_rnr_attributes(qp_attr)
        qp_access = ibv_access_flags.IBV_ACCESS_LOCAL_WRITE | ibv_access_flags.IBV_ACCESS_REMOTE_WRITE | \
                    ibv_access_flags.IBV_ACCESS_REMOTE_ATOMIC | ibv_access_flags.IBV_ACCESS_REMOTE_READ
        qp_attr.qp_access_flags = qp_access
        gr = GlobalRoute(dgid=self.ctx.query_gid(self.ib_port, self.gid_index),
                         sgid_index=self.gid_index)
        ah_attr = AHAttr(port_num=self.ib_port, is_global=1, gr=gr,
                         dlid=self.port_attr.lid)
        qp_attr.ah_attr = ah_attr
        return qp_attr

    def create_qp_init_attr(self, send_ops_flags=0):
        comp_mask = ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_PD
        if send_ops_flags:
            comp_mask |= ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS
        return QPInitAttrEx(cap=self.create_qp_cap(), pd=self.pd, scq=self.cq,
                            rcq=self.cq, srq=self.srq, qp_type=ibv_qp_type.IBV_QPT_DRIVER,
                            send_ops_flags=send_ops_flags, comp_mask=comp_mask,
                            sq_sig_all=1)

    def create_qps(self):
        # Create the DCI QPs.
        qp_init_attr = self.create_qp_init_attr(self.send_ops_flags)
        try:
            for _ in range(self.qp_count):
                comp_mask = mlx5dv_qp_init_attr_mask.MLX5DV_QP_INIT_ATTR_MASK_DC
                if self.create_flags:
                    comp_mask |= mlx5dv_qp_init_attr_mask.MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS
                attr = Mlx5DVQPInitAttr(comp_mask=comp_mask,
                                        create_flags=self.create_flags,
                                        dc_init_attr=Mlx5DVDCInitAttr())
                qp = Mlx5QP(self.ctx, qp_init_attr, attr)
                self.qps.append(qp)
                self.qps_num.append(qp.qp_num)
                self.psns.append(random.getrandbits(24))

            # Create the DCT QP.
            qp_init_attr = self.create_qp_init_attr()
            dc_attr = Mlx5DVDCInitAttr(dc_type=mlx5dv_dc_type.MLX5DV_DCTYPE_DCT,
                                       dct_access_key=DCT_KEY)
            attr = Mlx5DVQPInitAttr(comp_mask=mlx5dv_qp_init_attr_mask.MLX5DV_QP_INIT_ATTR_MASK_DC,
                                    dc_init_attr=dc_attr)
            self.dct_qp = Mlx5QP(self.ctx, qp_init_attr, attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest(f'Create DC QP is not supported')
            raise ex


class Mlx5DcStreamsRes(Mlx5DcResources):
    def __init__(self, dev_name, ib_port, gid_index, send_ops_flags,
                 qp_count=1, create_flags=0):
        self.bad_flow = 0
        self.mr_bad_flow = False
        self.stream_check = False
        super().__init__(dev_name, ib_port, gid_index, send_ops_flags,
                         qp_count, create_flags)

    def reset_qp(self, qp_idx):
        qp_attr = QPAttr(qp_state=ibv_qp_state.IBV_QPS_RESET)
        self.qps[qp_idx].modify(qp_attr, ibv_qp_attr_mask.IBV_QP_STATE)
        self.qps[qp_idx].to_rts(qp_attr)
        self.qp_stream_errors[qp_idx][0] = 0

    def get_stream_id(self, qp_idx):
        return self.current_qp_stream_id[qp_idx]

    def generate_stream_id(self, qp_idx):
        self.current_qp_stream_id[qp_idx] += 1
        # Reset stream id to check double-usage
        if self.current_qp_stream_id[qp_idx] > self.dcis[qp_idx]['stream']+2:
            self.current_qp_stream_id[qp_idx] = 1
        return self.current_qp_stream_id[qp_idx]

    def dci_reset_stream_id(self, qp_idx):
        stream_id = self.get_stream_id(qp_idx)
        Mlx5QP.modify_dci_stream_channel_id(self.qps[qp_idx], stream_id)
        # Check once if error raised when reset wrong stream id
        if self.stream_check:
            try:
                Mlx5QP.modify_dci_stream_channel_id(self.qps[qp_idx],
                                                    stream_id+1)
            except PyverbsRDMAError as ex:
                self.stream_check = False

    def bad_flow_handler_qp(self, qp_idx, status, reset=False):
        str_id = self.get_stream_id(qp_idx)
        bt_stream = (1 << str_id)

        if status == ibv_wc_status.IBV_WC_LOC_PROT_ERR:
            self.qp_stream_errors[qp_idx][1] += 1
            if (self.qp_stream_errors[qp_idx][0] & bt_stream) != 0:
                raise PyverbsError(f'Dublicate error from stream id {str_id}')
            self.qp_stream_errors[qp_idx][0] |= bt_stream
        if status == ibv_wc_status.IBV_WC_WR_FLUSH_ERR:
            qp_attr, _ = self.qps[qp_idx].query(ibv_qp_attr_mask.IBV_QP_STATE)
            if qp_attr.cur_qp_state == ibv_qp_state.IBV_QPS_ERR and reset:
                if self.qp_stream_errors[qp_idx][1] != self.dcis[qp_idx]['errored']:
                    msg = f'QP {qp_idx} in ERR state with wrong number of counter'
                    raise PyverbsError(msg)
                self.reset_qp(qp_idx)
                self.qp_stream_errors[qp_idx][2] = True

        return True

    def bad_flow_handling(self, qp_idx, status, reset=False):
        if self.bad_flow == DCI_TEST_GOOD_FLOW:
            return False
        if self.bad_flow == DCI_TEST_BAD_FLOW_WITH_RESET:
            self.qp_stream_errors[qp_idx][1] += 1
            if reset:
                self.dci_reset_stream_id(qp_idx)
            return True
        if self.bad_flow == DCI_TEST_BAD_FLOW_WITHOUT_RESET:
            return self.bad_flow_handler_qp(qp_idx, status, reset)
        return False

    def set_bad_flow(self, bad_flow):
        self.bad_flow = bad_flow
        if self.bad_flow:
            if bad_flow == DCI_TEST_BAD_FLOW_WITH_RESET and self.log_dci_errored == 0:
                raise unittest.SkipTest('DCS test of bad flow with reset is not '
                                        'supported when HCA_CAP.log_dci_errored is 0')
            self.pd_bad = PD(self.ctx)
            self.mr_bad_flow = False
        if bad_flow == DCI_TEST_BAD_FLOW_WITH_RESET:
            self.stream_check = True

    def is_bad_flow(self, qp_idx):
        cnt = self.get_stream_id(qp_idx)
        if self.bad_flow == DCI_TEST_GOOD_FLOW:
            return False
        if self.bad_flow == DCI_TEST_BAD_FLOW_WITH_RESET:
            if (cnt % 3) != 0:
                return False
            self.qp_stream_errors[qp_idx][0] += 1
        if self.bad_flow == DCI_TEST_BAD_FLOW_WITHOUT_RESET:
            if self.qp_stream_errors[qp_idx][2]:
                return False
        return True

    def check_bad_flow(self, qp_idx):
        change_mr = False
        if self.is_bad_flow(qp_idx):
            if not self.mr_bad_flow:
                self.mr_bad_flow = True
                pd = self.pd_bad
                change_mr = True
        else:
            if self.mr_bad_flow:
                self.mr_bad_flow = False
                pd = self.pd
                change_mr = True
        if change_mr:
            self.mr.rereg(flags=ibv_rereg_mr_flags.IBV_REREG_MR_CHANGE_PD, pd=pd,
                          addr=0, length=0, access=0)

    def check_after_traffic(self):
        if self.bad_flow == DCI_TEST_BAD_FLOW_WITH_RESET:
            for errs in self.qp_stream_errors:
                if errs[0] != errs[1]:
                    msg = f'Number of qp_stream_errors {errs[0]} not same '\
                          f'as number of catches {errs[1]}'
                    raise PyverbsError(msg)
            if self.stream_check:
                msg = 'Reset of good stream id does not create exception'
                raise PyverbsError(msg)

    def generate_dci_attr(self, qpn):
        # This array contains current number of log_dci_streams
        # and log_dci_errored values per qp. For 1-st qp number
        # of streams greater than number of errored and vice-versa
        # for the 2nd qp.
        qp_arr = {0: [3, 2], 1: [2, 3]}
        try:
            dci_caps = self.ctx.query_mlx5_device().dci_streams_caps
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Get DCI caps is not supported')
            raise ex
        if not dci_caps or dci_caps['max_log_num_concurent'] == 0:
            raise unittest.SkipTest('DCI caps is not supported by HW')
        self.log_dci_streams = min(qp_arr.get(qpn, [1,1])[0],
                                   dci_caps['max_log_num_concurent'])
        self.log_dci_errored = min(qp_arr.get(qpn, [1,1])[1],
                                   dci_caps['max_log_num_errored'])

    def create_qps(self):
        # Create the DCI QPs.
        qp_init_attr = self.create_qp_init_attr(self.send_ops_flags)
        self.dcis = {}
        # This array contains current stream id
        self.current_qp_stream_id = {}
        # This array counts different errors in bad_flow
        self.qp_stream_errors = []
        comp_mask = mlx5dv_qp_init_attr_mask.MLX5DV_QP_INIT_ATTR_MASK_DC | \
                    mlx5dv_qp_init_attr_mask.MLX5DV_QP_INIT_ATTR_MASK_DCI_STREAMS
        try:
            for qpn in range(self.qp_count):
                if self.create_flags:
                    comp_mask |= mlx5dv_qp_init_attr_mask.MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS
                self.generate_dci_attr(qpn)
                stream_ctx = Mlx5DCIStreamInitAttr(self.log_dci_streams,
                                                   self.log_dci_errored)
                self.dcis[qpn] = {'stream': 1 << self.log_dci_streams,
                                  'errored': 1 << self.log_dci_errored}
                attr = Mlx5DVQPInitAttr(comp_mask=comp_mask,
                                        create_flags=self.create_flags,
                                        dc_init_attr=Mlx5DVDCInitAttr(dci_streams=stream_ctx))
                qp = Mlx5QP(self.ctx, qp_init_attr, attr)
                self.qps.append(qp)
                # Different values for start point of stream id per qp
                self.current_qp_stream_id[qpn] = qpn
                # Array of errors for bad_flow
                # For DCI_TEST_BAD_FLOW_WITH_RESET
                #  First element - number of injected bad flows
                #  Second element - number of exceptions from bad flows
                # For DCI_TEST_BAD_FLOW_WITHOUT_RESET
                #  First element - bitmap of bad flow streams
                #  Second element - number of exceptions from bad flows
                #  Third element - flag if reset of qp been executed
                self.qp_stream_errors.append([0, 0, False])
                self.qps_num.append(qp.qp_num)
                self.psns.append(random.getrandbits(24))
            # Create the DCT QP.
            qp_init_attr = self.create_qp_init_attr()
            dc_attr = Mlx5DVDCInitAttr(dc_type=mlx5dv_dc_type.MLX5DV_DCTYPE_DCT,
                                       dct_access_key=DCT_KEY)
            attr = Mlx5DVQPInitAttr(comp_mask=mlx5dv_qp_init_attr_mask.MLX5DV_QP_INIT_ATTR_MASK_DC,
                                    dc_init_attr=dc_attr)
            self.dct_qp = Mlx5QP(self.ctx, qp_init_attr, attr)
        except PyverbsRDMAError as ex:
            if ex.error_code in [errno.EOPNOTSUPP, errno.EPROTONOSUPPORT]:
                raise unittest.SkipTest('Create DC QP is not supported')
            raise ex

    @staticmethod
    def traffic_with_bad_flow(client, server, iters, gid_idx, port):
        """
        Runs basic traffic with bad flow between two sides
        :param client: client side, clients base class is BaseTraffic
        :param server: server side, servers base class is BaseTraffic
        :param iters: number of traffic iterations
        :param gid_idx: local gid index
        :param port: IB port
        :return: None
        """
        import tests.utils as u
        send_op = ibv_wr_opcode.IBV_WR_SEND
        ah_client = u.get_global_ah(client, gid_idx, port)
        s_recv_wr = u.get_recv_wr(server)
        c_recv_wr = u.get_recv_wr(client)
        for qp_idx in range(server.qp_count):
            # Prepare the receive queue with RecvWR
            u.post_recv(client, c_recv_wr, qp_idx=qp_idx)
            u.post_recv(server, s_recv_wr, qp_idx=qp_idx)
        read_offset = 0
        for _ in range(iters):
            for qp_idx in range(server.qp_count):
                _, c_send_object = u.get_send_elements(client, False)
                u.send(client, c_send_object, send_op, True, qp_idx,
                       ah_client, False)
                try:
                    wcs = u._poll_cq(client.cq)
                except PyverbsError as ex:
                    if client.bad_flow_handling(qp_idx, ibv_wc_status.IBV_WC_SUCCESS, True):
                        continue
                    raise ex
                else:
                    if wcs[0].status != ibv_wc_status.IBV_WC_SUCCESS and \
                            client.bad_flow_handling(qp_idx, wcs[0].status, True):
                        continue

                u.poll_cq(server.cq)
                u.post_recv(server, s_recv_wr, qp_idx=qp_idx)
                msg_received = server.mr.read(server.msg_size, read_offset)
                u.validate(msg_received, True, server.msg_size)
        client.check_after_traffic()


class WqAttrs:
    def __init__(self):
        super().__init__()
        self.wqe_num = 0
        self.wqe_size = 0
        self.wq_size = 0
        self.head = 0
        self.post_idx = 0
        self.wqe_shift = 0
        self.offset = 0

    def __str__(self):
        return str(vars(self))

    def __format__(self, format_spec):
        return str(self).__format__(format_spec)


class CqAttrs:
    def __init__(self):
        super().__init__()
        self.cons_idx = 0
        self.cqe_size = 64
        self.ncqes = 256

    def __str__(self):
        return str(vars(self))

    def __format__(self, format_spec):
        return str(self).__format__(format_spec)


class QueueAttrs:
    def __init__(self):
        self.rq = WqAttrs()
        self.sq = WqAttrs()
        self.cq = CqAttrs()

    def __str__(self):
        print_format = '{}:\n\t{}\n'
        return print_format.format('RQ Attributes', self.rq) + \
               print_format.format('SQ Attributes', self.sq) + \
               print_format.format('CQ Attributes', self.cq)


class Mlx5DevxRcResources(BaseResources):
    """
    Creates all the DevX resources needed for a traffic-ready RC DevX QP,
    including methods to transit the WQs into RTS state.
    It also includes traffic methods for post send/receive and poll.
    The class currently supports post send with immediate, but can be
    easily extended to support other opcodes in the future.
    """
    def __init__(self, dev_name, ib_port, gid_index, msg_size=1024, activate_port_state=False,
                 send_dbr_mode=0):
        from tests.mlx5_prm_structs import SendDbrMode
        super().__init__(dev_name, ib_port, gid_index)
        self.umems = {}
        self.send_dbr_mode = send_dbr_mode
        self.msg_size = msg_size
        self.num_msgs = 1000
        self.imm = 0x03020100
        self.uar = {}
        self.max_recv_sge = 1
        self.eqn = None
        self.pd = None
        self.dv_pd = None
        self.mr = None
        self.msi_vector = None
        self.eq = None
        self.cq = None
        self.qp = None
        self.qpn = None
        self.psn = None
        self.lid = None
        self.gid = [0, 0, 0, 0]
        # Remote attrs
        self.rqpn = None
        self.rpsn = None
        self.rlid = None
        self.rgid = [0, 0, 0, 0]
        self.rmac = None
        self.devx_objs = []
        self.qattr = QueueAttrs()
        self.with_odp = False
        self.user_addr = None
        if activate_port_state:
            start_state_t = time.perf_counter()
            self.change_port_state_with_registers(PortStatus.MLX5_PORT_UP)
            admin_status, oper_status = self.query_port_state_with_registers()
            while admin_status != PortStatus.MLX5_PORT_UP or oper_status != PortStatus.MLX5_PORT_UP:
                if time.perf_counter() - start_state_t >= PORT_STATE_TIMEOUT:
                    raise PyverbsRDMAError('Could not change the port state to UP')
                self.change_port_state_with_registers(PortStatus.MLX5_PORT_UP)
                admin_status, oper_status = self.query_port_state_with_registers()
                time.sleep(1)

            mad_port_state = self.query_port_state_with_mads(ib_port)
            while mad_port_state < PortState.ACTIVE:
                if time.perf_counter() - start_state_t >= PORT_STATE_TIMEOUT:
                    raise PyverbsRDMAError('Could not change the port state to UP')
                time.sleep(1)
                mad_port_state = self.query_port_state_with_mads(ib_port)
        if self.send_dbr_mode != SendDbrMode.DBR_VALID:
            self.check_cap_send_dbr_mode()
        self.init_resources()

    def get_wqe_data_segment(self):
        return WqeDataSeg(self.mr.length, self.mr.lkey, self.mr.buf)

    def change_port_state_with_registers(self, state):
        from tests.mlx5_prm_structs import PaosReg
        paos_in = PaosReg(local_port=self.ib_port, admin_status=state, ase=1)
        self.access_paos_register(paos_in)

    def query_port_state_with_registers(self):
        from tests.mlx5_prm_structs import PaosReg
        paos_in = PaosReg(local_port=self.ib_port)
        paos_out = self.access_paos_register(paos_in)
        return paos_out.admin_status, paos_out.oper_status

    def access_paos_register(self, paos_in, op_mod=0):  # op_mod: 0 - write / 1 - read
        from tests.mlx5_prm_structs import AccessPaosRegisterIn, \
            AccessPaosRegisterOut, DevxOps
        paos_reg_in = AccessPaosRegisterIn(op_mod=op_mod,
                                           register_id=DevxOps.MLX5_CMD_OP_ACCESS_REGISTER_PAOS,
                                           data=paos_in)
        cmd_out = self.ctx.devx_general_cmd(paos_reg_in, len(AccessPaosRegisterOut()))
        paos_reg_out = AccessPaosRegisterOut(cmd_out)
        if paos_reg_out.status:
            raise PyverbsRDMAError(f'Failed to access PAOS register ({paos_reg_out.syndrome})')
        return paos_reg_out.data

    def query_port_state_with_mads(self, ib_port):
        from tests.mlx5_prm_structs import IbSmp
        in_mad = IbSmp(base_version=1, mgmt_class=IB_MGMT_CLASS_SUBN_LID_ROUTED,
                       class_version=1, method=IB_MGMT_METHOD_GET,
                       attr_id=IB_SMP_ATTR_PORT_INFO, attr_mod=ib_port)
        ib_smp_out = IbSmp(self._send_mad_cmd(ib_port, in_mad, 0x3))
        return ib_smp_out.data[32] & 0xf

    def _send_mad_cmd(self, ib_port, in_mad, op_mod):
        from tests.mlx5_prm_structs import MadIfcIn, MadIfcOut
        mad_ifc_in = MadIfcIn(op_mod=op_mod, port=ib_port, mad=in_mad)
        cmd_out = self.ctx.devx_general_cmd(mad_ifc_in, len(MadIfcOut()))
        mad_ifc_out = MadIfcOut(cmd_out)
        if mad_ifc_out.status:
            raise PyverbsRDMAError(f'Failed to send MAD with syndrome ({mad_ifc_out.syndrome})')
        return mad_ifc_out.mad

    def check_cap_send_dbr_mode(self):
        """
        Check the capability of the dbr less.
        If the HCA cap have HCA cap 2, check if in HCA cap2 0x20(HCA CAP 2) + 0x1(current)
        have the send_dbr_mode_no_dbr_ext.
        """
        from tests.mlx5_prm_structs import QueryCmdHcaCap2Out, \
            QueryHcaCapIn, QueryCmdHcaCapOut, QueryHcaCapOp, QueryHcaCapMod, SendDbrMode
        self.create_context()
        query_cap_in = QueryHcaCapIn(op_mod=0x1)
        query_cap_out = QueryCmdHcaCapOut(self.ctx.devx_general_cmd(
            query_cap_in, len(QueryCmdHcaCapOut())))
        if query_cap_out.status:
            raise PyverbsRDMAError('Failed to query general HCA CAPs with syndrome '
                                   f'({query_cap_out.syndrome}')

        if not query_cap_out.capability.hca_cap_2:
            raise unittest.SkipTest("The device doesn't support general HCA CAPs 2")
        query_cap2_in = QueryHcaCapIn(op_mod=(QueryHcaCapOp.HCA_CAP_2 << 0x1) | \
                                              QueryHcaCapMod.CURRENT)
        query_cap2_out = QueryCmdHcaCap2Out(self.ctx.devx_general_cmd(
            query_cap2_in, len(QueryCmdHcaCap2Out())))
        if self.send_dbr_mode == SendDbrMode.NO_DBR_EXT and \
                not query_cap2_out.capability.send_dbr_mode_no_dbr_ext:
            raise unittest.SkipTest("The device doesn't support send_dbr_mode_no_dbr_ext cap")

        if self.send_dbr_mode == SendDbrMode.NO_DBR_INT and \
                not query_cap2_out.capability.send_dbr_mode_no_dbr_int:
            raise unittest.SkipTest("The device doesn't support send_dbr_mode_no_dbr_int cap")

    def init_resources(self):
        if not self.is_eth():
            self.query_lid()
        else:
            is_gid_available(self.gid_index)
            self.query_gid()
        self.create_pd()
        self.create_mr()
        self.query_eqn()
        self.create_uar()
        self.create_queue_attrs()
        self.create_eq()
        self.create_cq()
        self.create_qp()
        # Objects closure order is important, and must be done manually in DevX
        self.devx_objs = [self.qp, self.cq] + list(self.uar.values()) + list(self.umems.values()) + [self.msi_vector, self.eq]


    def query_lid(self):
        from tests.mlx5_prm_structs import QueryHcaVportContextIn, \
            QueryHcaVportContextOut, QueryHcaCapIn, QueryCmdHcaCapOut

        query_cap_in = QueryHcaCapIn(op_mod=0x1)
        query_cap_out = QueryCmdHcaCapOut(self.ctx.devx_general_cmd(
            query_cap_in, len(QueryCmdHcaCapOut())))
        if query_cap_out.status:
            raise PyverbsRDMAError('Failed to query general HCA CAPs with syndrome '
                                   f'({query_cap_out.syndrome}')
        port_num = self.ib_port if query_cap_out.capability.num_ports >= 2 else 0
        query_port_in = QueryHcaVportContextIn(port_num=port_num)
        query_port_out = QueryHcaVportContextOut(self.ctx.devx_general_cmd(
            query_port_in, len(QueryHcaVportContextOut())))
        if query_port_out.status:
            raise PyverbsRDMAError('Failed to query vport with syndrome '
                                   f'({query_port_out.syndrome})')
        self.lid = query_port_out.hca_vport_context.lid

    def query_gid(self):
        gid = self.ctx.query_gid(self.ib_port, self.gid_index).gid.split(':')
        for i in range(0, len(gid), 2):
            self.gid[int(i/2)] = int(gid[i] + gid[i+1], 16)

    def is_eth(self):
        from tests.mlx5_prm_structs import QueryHcaCapIn, \
            QueryCmdHcaCapOut

        query_cap_in = QueryHcaCapIn(op_mod=0x1)
        query_cap_out = QueryCmdHcaCapOut(self.ctx.devx_general_cmd(
            query_cap_in, len(QueryCmdHcaCapOut())))
        if query_cap_out.status:
            raise PyverbsRDMAError('Failed to query general HCA CAPs with syndrome '
                                   f'({query_cap_out.syndrome})')
        return query_cap_out.capability.port_type  # 0:IB, 1:ETH

    @staticmethod
    def roundup_pow_of_two(val):
        return pow(2, math.ceil(math.log2(val)))

    def create_queue_attrs(self):
        # RQ calculations
        wqe_size = WqeDataSeg.sizeof() * self.max_recv_sge
        self.qattr.rq.wqe_size = self.roundup_pow_of_two(wqe_size)
        max_recv_wr = self.roundup_pow_of_two(self.num_msgs)
        self.qattr.rq.wq_size = max(self.qattr.rq.wqe_size * max_recv_wr,
                                    MLX5_SEND_WQE_BB)
        self.qattr.rq.wqe_num = math.ceil(self.qattr.rq.wq_size / self.qattr.rq.wqe_size)
        self.qattr.rq.wqe_shift = int(math.log2(self.qattr.rq.wqe_size - 1)) + 1

        # SQ calculations
        self.qattr.sq.offset = self.qattr.rq.wq_size
        # 192 = max overhead size of all structs needed for all operations in RC
        wqe_size = 192 + WqeDataSeg.sizeof()
        # Align wqe size to MLX5_SEND_WQE_BB
        self.qattr.sq.wqe_size = (wqe_size + MLX5_SEND_WQE_BB - 1) & ~(MLX5_SEND_WQE_BB - 1)
        self.qattr.sq.wq_size = self.roundup_pow_of_two(self.qattr.sq.wqe_size * self.num_msgs)
        self.qattr.sq.wqe_num = math.ceil(self.qattr.sq.wq_size / MLX5_SEND_WQE_BB)
        self.qattr.sq.wqe_shift = int(math.log2(MLX5_SEND_WQE_BB))

    def create_context(self):
        try:
            attr = Mlx5DVContextAttr(mlx5dv_context_attr_flags.MLX5DV_CONTEXT_FLAGS_DEVX)
            self.ctx = Mlx5Context(attr, self.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening mlx5 DevX context is not supported')

    def create_pd(self):
        self.pd = PD(self.ctx)
        self.dv_pd = Mlx5DvObj(mlx5dv_obj_type.MLX5DV_OBJ_PD, pd=self.pd).dvpd

    def create_mr(self):
        access = ibv_access_flags.IBV_ACCESS_REMOTE_WRITE | ibv_access_flags.IBV_ACCESS_LOCAL_WRITE | \
                 ibv_access_flags.IBV_ACCESS_REMOTE_READ
        self.mr = MR(self.pd, self.msg_size, access)

    def create_umem(self, size,
                    access=ibv_access_flags.IBV_ACCESS_LOCAL_WRITE,
                    alignment=resource.getpagesize()):
        return Mlx5UMEM(self.ctx, size=size, alignment=alignment, access=access)

    def create_uar(self):
        self.uar['qp'] = Mlx5UAR(self.ctx, _MLX5DV_UAR_ALLOC_TYPE_NC)
        self.uar['cq'] = Mlx5UAR(self.ctx, _MLX5DV_UAR_ALLOC_TYPE_NC)
        if not self.uar['cq'].page_id or not self.uar['qp'].page_id:
            raise PyverbsRDMAError('Failed to allocate UAR')

    def query_eqn(self):
        self.eqn = self.ctx.devx_query_eqn(0)

    def create_cq(self):
        from tests.mlx5_prm_structs import CreateCqIn, SwCqc, CreateCqOut

        cq_size = self.roundup_pow_of_two(self.qattr.cq.cqe_size * self.qattr.cq.ncqes)
        # Align to page size
        pg_size = resource.getpagesize()
        cq_size = (cq_size + pg_size - 1) & ~(pg_size - 1)
        self.umems['cq'] = self.create_umem(size=cq_size)
        self.umems['cq_dbr'] = self.create_umem(size=8, alignment=8)
        log_cq_size = math.ceil(math.log2(self.qattr.cq.ncqes))
        cmd_in = CreateCqIn(cq_umem_valid=1, cq_umem_id=self.umems['cq'].umem_id,
                            sw_cqc=SwCqc(c_eqn=self.eqn, uar_page=self.uar['cq'].page_id,
                                         log_cq_size=log_cq_size, dbr_umem_valid=1,
                                         dbr_umem_id=self.umems['cq_dbr'].umem_id))
        self.cq = Mlx5DevxObj(self.ctx, cmd_in, len(CreateCqOut()))

    def create_qp(self):
        self.psn = random.getrandbits(24)
        from tests.mlx5_prm_structs import SwQpc, CreateQpIn, DevxOps,\
            CreateQpOut, CreateCqOut

        self.psn = random.getrandbits(24)
        qp_size = self.roundup_pow_of_two(self.qattr.rq.wq_size + self.qattr.sq.wq_size)
        # Align to page size
        pg_size = resource.getpagesize()
        qp_size = (qp_size + pg_size - 1) & ~(pg_size - 1)
        self.umems['qp'] = self.create_umem(size=qp_size)
        self.umems['qp_dbr'] = self.create_umem(size=8, alignment=8)
        log_rq_size = int(math.log2(self.qattr.rq.wqe_num - 1)) + 1
        # Size of a receive WQE is 16*pow(2, log_rq_stride)
        log_rq_stride = self.qattr.rq.wqe_shift - 4
        log_sq_size = int(math.log2(self.qattr.sq.wqe_num - 1)) + 1
        cqn = CreateCqOut(self.cq.out_view).cqn
        qpc = SwQpc(st=DevxOps.MLX5_QPC_ST_RC, pd=self.dv_pd.pdn,
                    pm_state=DevxOps.MLX5_QPC_PM_STATE_MIGRATED,
                    log_rq_size=log_rq_size, log_sq_size=log_sq_size, ts_format=0x1,
                    log_rq_stride=log_rq_stride, uar_page=self.uar['qp'].page_id,
                    cqn_snd=cqn, cqn_rcv=cqn, dbr_umem_id=self.umems['qp_dbr'].umem_id,
                    dbr_umem_valid=1, send_dbr_mode=self.send_dbr_mode)
        cmd_in = CreateQpIn(sw_qpc=qpc, wq_umem_id=self.umems['qp'].umem_id,
                            wq_umem_valid=1)
        self.qp = Mlx5DevxObj(self.ctx, cmd_in, len(CreateQpOut()))
        self.qpn = CreateQpOut(self.qp.out_view).qpn

    def create_eq(self):
        pass

    def to_rts(self):
        """
        Moves the created QP to RTS state by modifying it using DevX through all
        the needed states with all the required attributes.
        rlid, rpsn, rqpn and rgid (when valid) must be already updated before
        calling this method.
        """
        from tests.mlx5_prm_structs import DevxOps, ModifyQpIn, ModifyQpOut,\
            CreateQpOut, SwQpc
        cmd_out_len = len(ModifyQpOut())

        # RST2INIT
        qpn = CreateQpOut(self.qp.out_view).qpn
        swqpc = SwQpc(rre=1, rwe=1)
        swqpc.primary_address_path.vhca_port_num = self.ib_port
        cmd_in = ModifyQpIn(opcode=DevxOps.MLX5_CMD_OP_RST2INIT_QP, qpn=qpn,
                            sw_qpc=swqpc)
        self.qp.modify(cmd_in, cmd_out_len)

        # INIT2RTR
        swqpc = SwQpc(mtu=PATH_MTU, log_msg_max=20, remote_qpn=self.rqpn,
                      min_rnr_nak=MIN_RNR_TIMER, next_rcv_psn=self.rpsn)
        swqpc.primary_address_path.vhca_port_num = self.ib_port
        swqpc.primary_address_path.rlid = self.rlid
        if self.is_eth():
            # GID field is a must for Eth (or if GRH is set in IB)
            swqpc.primary_address_path.rgid_rip = self.rgid
            swqpc.primary_address_path.rmac = self.rmac
            swqpc.primary_address_path.src_addr_index = self.gid_index
            swqpc.primary_address_path.hop_limit = tests.utils.PacketConsts.TTL_HOP_LIMIT
            # UDP sport must be reserved for roce v1 and v1.5
            if self.ctx.query_gid_type(self.ib_port, self.gid_index) == ibv_gid_type_sysfs.IBV_GID_TYPE_SYSFS_ROCE_V2:
                swqpc.primary_address_path.udp_sport = 0xdcba
        else:
            swqpc.primary_address_path.rlid = self.rlid
        cmd_in = ModifyQpIn(opcode=DevxOps.MLX5_CMD_OP_INIT2RTR_QP, qpn=qpn,
                            sw_qpc=swqpc)
        self.qp.modify(cmd_in, cmd_out_len)

        # RTR2RTS
        swqpc = SwQpc(retry_count=RETRY_CNT, rnr_retry=RNR_RETRY,
                      next_send_psn=self.psn, log_sra_max=MAX_RDMA_ATOMIC)
        swqpc.primary_address_path.vhca_port_num = self.ib_port
        swqpc.primary_address_path.ack_timeout = TIMEOUT
        cmd_in = ModifyQpIn(opcode=DevxOps.MLX5_CMD_OP_RTR2RTS_QP, qpn=qpn,
                            sw_qpc=swqpc)
        self.qp.modify(cmd_in, cmd_out_len)

    def pre_run(self, rpsn, rqpn, rgid=0, rlid=0, rmac=0):
        """
        Configure Resources before running traffic
        :param rpsns: Remote PSN (packet serial number)
        :param rqpn: Remote QP number
        :param rgid: Remote GID
        :param rlid: Remote LID
        :param rmac: Remote MAC (valid for RoCE)
        :return: None
        """
        self.rpsn = rpsn
        self.rqpn = rqpn
        self.rgid = rgid
        self.rlid = rlid
        self.rmac = rmac
        self.to_rts()

    def post_send(self):
        """
        Posts one send WQE to the SQ by doing all the required work such as
        building the control/data segments, updating and ringing the dbr,
        updating the producer indexes, etc.
        """
        from tests.mlx5_prm_structs import SendDbrMode
        buffer_address = self.uar['qp'].reg_addr
        if self.send_dbr_mode == SendDbrMode.NO_DBR_EXT:
            # Address of DB blueflame register
            buffer_address = self.uar['qp'].base_addr + DB_BF_DBR_LESS_BUF_OFFSET

        idx = self.qattr.sq.post_idx if self.qattr.sq.post_idx < self.qattr.sq.wqe_num else 0
        buf_offset = self.qattr.sq.offset + (idx << MLX5_SEND_WQE_SHIFT)
        # Prepare WQE
        imm_be32 = struct.unpack("<I", struct.pack(">I", self.imm + self.qattr.sq.post_idx))[0]
        ctrl_seg = WqeCtrlSeg(imm=imm_be32, fm_ce_se=MLX5_WQE_CTRL_CQ_UPDATE)
        data_seg = self.get_wqe_data_segment()
        ctrl_seg.opmod_idx_opcode = (self.qattr.sq.post_idx & 0xffff) << 8 | MLX5_OPCODE_SEND_IMM
        size_in_octowords = int((ctrl_seg.sizeof() + data_seg.sizeof()) / 16)
        ctrl_seg.qpn_ds = self.qpn << 8 | size_in_octowords
        Wqe([ctrl_seg, data_seg], self.umems['qp'].umem_addr + buf_offset)
        self.qattr.sq.post_idx += int((size_in_octowords * 16 +
                                       MLX5_SEND_WQE_BB - 1) / MLX5_SEND_WQE_BB)
        # Make sure descriptors are written
        dma.udma_to_dev_barrier()
        if not self.send_dbr_mode:
            # Update the doorbell record
            mem.writebe32(self.umems['qp_dbr'].umem_addr,
                          self.qattr.sq.post_idx & 0xffff, MLX5_SND_DBR)
            dma.udma_to_dev_barrier()
        # Ring the doorbell and post the WQE
        dma.mmio_write64_as_be(buffer_address, mem.read64(ctrl_seg.addr))

    def post_recv(self):
        """
        Posts one receive WQE to the RQ by doing all the required work such as
        building the control/data segments, updating the dbr and the producer
        indexes.
        """
        buf_offset = self.qattr.rq.offset + self.qattr.rq.wqe_size * self.qattr.rq.head
        # Prepare WQE
        data_seg = self.get_wqe_data_segment()
        Wqe([data_seg], self.umems['qp'].umem_addr + buf_offset)
        # Update indexes
        self.qattr.rq.post_idx += 1
        self.qattr.rq.head = self.qattr.rq.head + 1 if self.qattr.rq.head + 1 < self.qattr.rq.wqe_num else 0
        # Update the doorbell record
        dma.udma_to_dev_barrier()
        mem.writebe32(self.umems['qp_dbr'].umem_addr,
                      self.qattr.rq.post_idx & 0xffff, MLX5_RCV_DBR)

    def poll_cq(self):
        """
        Polls the CQ once and updates the consumer index upon success.
        The CQE opcode and owner bit are checked and verified.
        This method does busy-waiting as long as it gets an empty CQE, until a
        timeout of POLL_CQ_TIMEOUT seconds.
        """
        idx = self.qattr.cq.cons_idx % self.qattr.cq.ncqes
        cq_owner_flip = not(not(self.qattr.cq.cons_idx & self.qattr.cq.ncqes))
        cqe_start_addr = self.umems['cq'].umem_addr + (idx * self.qattr.cq.cqe_size)
        cqe = None
        start_poll_t = time.perf_counter()
        while cqe is None:
            cqe = Mlx5Cqe64(cqe_start_addr)
            if (cqe.opcode == MLX5_CQE_INVALID) or \
                    (cqe.owner ^ cq_owner_flip) or cqe.is_empty():
                if time.perf_counter() - start_poll_t >= POLL_CQ_TIMEOUT:
                    raise PyverbsRDMAError(f'CQE #{self.qattr.cq.cons_idx} '
                                           f'is empty or invalid:\n{cqe.dump()}')
                cqe = None

        # After CQE ownership check, must do memory barrier and re-read the CQE.
        dma.udma_from_dev_barrier()
        cqe = Mlx5Cqe64(cqe_start_addr)

        if cqe.opcode == MLX5_CQE_RESP_ERR:
            raise PyverbsRDMAError(f'Got a CQE #{self.qattr.cq.cons_idx} '
                                   f'with responder error:\n{cqe.dump()}')
        elif cqe.opcode == MLX5_CQE_REQ_ERR:
            raise PyverbsRDMAError(f'Got a CQE #{self.qattr.cq.cons_idx} '
                                   f'with requester error:\n{cqe.dump()}')

        self.qattr.cq.cons_idx += 1
        mem.writebe32(self.umems['cq_dbr'].umem_addr,
                      self.qattr.cq.cons_idx & 0xffffff, MLX5_CQ_SET_CI)
        return cqe

    def close_resources(self):
        for obj in self.devx_objs:
            if obj:
                obj.close()


class Mlx5DevxTrafficBase(Mlx5RDMATestCase):
    """
    A base class for mlx5 DevX traffic tests.
    This class does not include any tests, but provides quick players (client,
    server) creation and provides a traffic method.
    """
    def tearDown(self):
        if self.server:
            self.server.close_resources()
        if self.client:
            self.client.close_resources()
        super().tearDown()

    def create_players(self, resources, **resource_arg):
        """
        Initialize tests resources.
        :param resources: The RDMA resources to use.
        :param resource_arg: Dictionary of args that specify the resources
                             specific attributes.
        :return: None
        """
        self.server = resources(**self.dev_info, **resource_arg)
        self.client = resources(**self.dev_info, **resource_arg)
        self.pre_run()

    def pre_run(self):
        self.server.pre_run(self.client.psn, self.client.qpn, self.client.gid,
                            self.client.lid, self.mac_addr)
        self.client.pre_run(self.server.psn, self.server.qpn, self.server.gid,
                            self.server.lid, self.mac_addr)

    def invalidate_mr_pages(self):
        if self.client.with_odp:
            mem.madvise(self.client.mr.buf, self.client.msg_size)
            self.client.mem_write('c' * self.client.msg_size, self.client.msg_size)
        if self.server.with_odp:
            mem.madvise(self.server.mr.buf, self.server.msg_size)

    def send_imm_traffic(self):
        self.client.mem_write('c' * self.client.msg_size, self.client.msg_size)
        for _ in range(self.client.num_msgs):
            cons_idx = self.client.qattr.cq.cons_idx
            self.invalidate_mr_pages()
            self.server.post_recv()
            self.client.post_send()
            # Poll client and verify received cqe opcode
            send_cqe = self.client.poll_cq()
            self.assertEqual(send_cqe.opcode, MLX5_CQE_REQ,
                             'Unexpected CQE opcode')
            # Poll server and verify received cqe opcode
            recv_cqe = self.server.poll_cq()
            self.assertEqual(recv_cqe.opcode, MLX5_CQE_RESP_SEND_IMM,
                             'Unexpected CQE opcode')
            msg_received = self.server.mem_read()
            # Validate data (of received message and immediate value)
            tests.utils.validate(msg_received, True, self.server.msg_size)
            imm_inval_pkey = recv_cqe.imm_inval_pkey
            if sys.byteorder == 'big':
                imm_inval_pkey = int.from_bytes(
                    imm_inval_pkey.to_bytes(4, byteorder='big'), 'little')
            self.assertEqual(imm_inval_pkey, self.client.imm + cons_idx)
            self.server.mem_write('s' * self.server.msg_size, self.server.msg_size)


class Mlx5RcResources(RCResources):
    def __init__(self, dev_name, ib_port, gid_index, **kwargs):
        self.dv_send_ops_flags = 0
        self.send_ops_flags = 0
        self.create_send_ops_flags()
        super().__init__(dev_name, ib_port, gid_index, **kwargs)

    def create_send_ops_flags(self):
        self.dv_send_ops_flags = 0
        self.send_ops_flags = ibv_qp_create_send_ops_flags.IBV_QP_EX_WITH_SEND

    def create_context(self):
        mlx5dv_attr = Mlx5DVContextAttr()
        try:
            self.ctx = Mlx5Context(mlx5dv_attr, name=self.dev_name)
        except PyverbsUserError as ex:
            raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
        except PyverbsRDMAError:
            raise unittest.SkipTest('Opening mlx5 context is not supported')

    def create_qp_init_attr(self):
        comp_mask = ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_PD | ibv_qp_init_attr_mask.IBV_QP_INIT_ATTR_SEND_OPS_FLAGS
        return QPInitAttrEx(cap=self.create_qp_cap(), pd=self.pd, scq=self.cq,
                            rcq=self.cq, qp_type=ibv_qp_type.IBV_QPT_RC,
                            send_ops_flags=self.send_ops_flags,
                            comp_mask=comp_mask)

    def create_qps(self):
        try:
            qp_init_attr = self.create_qp_init_attr()
            comp_mask = mlx5dv_qp_init_attr_mask.MLX5DV_QP_INIT_ATTR_MASK_QP_CREATE_FLAGS
            if self.dv_send_ops_flags:
                comp_mask |= mlx5dv_qp_init_attr_mask.MLX5DV_QP_INIT_ATTR_MASK_SEND_OPS_FLAGS
            attr = Mlx5DVQPInitAttr(comp_mask=comp_mask,
                                    send_ops_flags=self.dv_send_ops_flags)
            qp = Mlx5QP(self.ctx, qp_init_attr, attr)
            self.qps.append(qp)
            self.qps_num.append(qp.qp_num)
            self.psns.append(random.getrandbits(24))
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create Mlx5DV QP is not supported')
            raise ex

    def create_cq(self):
        """
        Initializes self.cq with a dv_cq
        :return: None
        """
        dvcq_init_attr = Mlx5DVCQInitAttr()
        try:
            self.cq = Mlx5CQ(self.ctx, CqInitAttrEx(), dvcq_init_attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                raise unittest.SkipTest('Create Mlx5DV CQ is not supported')
            raise ex


def create_privileged_context(agr_obj):
    """
    Creates a mlx5 privileged context.
    :param agr_obj: Aggregation object which contains all resources necessary.
    """
    fds_paths = ['/dev/infiniband/mlx5_perm_ctrl_local',
                     '/dev/infiniband/mlx5_perm_ctrl_other_vhca']
    open_fds = []
    try:
        for file_path in fds_paths:
            fd = open(file_path, 'rb')
            open_fds.append(fd)
        agr_obj.fds = FdArr(arr=[fd.fileno() for fd in open_fds], count=len(open_fds))
        attr = Mlx5DVContextAttr(flags=mlx5dv_context_attr_flags.MLX5DV_CONTEXT_FLAGS_DEVX,
                                    comp_mask=mlx5dv_context_attr_comp_mask.MLX5DV_CONTEXT_ATTR_MASK_FD_ARRAY,
                                    fds=agr_obj.fds)
        agr_obj.ctx = Mlx5Context(attr, agr_obj.dev_name)
        for fd in open_fds: fd.close()
    except FileNotFoundError:
        for fd in open_fds: fd.close()
        raise unittest.SkipTest(f'FDs file not found')
    except PyverbsUserError as ex:
        for fd in open_fds: fd.close()
        raise unittest.SkipTest(f'Could not open mlx5 context ({ex})')
    except PyverbsRDMAError as ex:
        for fd in open_fds: fd.close()
        raise unittest.SkipTest(f'Opening mlx5 DevX context is not supported ({ex})')


class Mlx5PrivilegedRC(Mlx5RcResources):
    def __init__(self, dev_name, ib_port, gid_index, msg_size=1024, **kwargs):
        """
        Initialize mlx5 DV privileged context resources based on Mlx5RcResources.
        :param dev_name: Device name to be used
        :param ib_port: IB port of the device to use
        :param gid_index: Which GID index to use
        :param msg_size: The resource msg size
        :param kwargs: General arguments
        """
        self.open_fds = []
        super().__init__(dev_name, ib_port, gid_index, msg_size=msg_size, **kwargs)

    def create_context(self):
        return create_privileged_context(self)

    def close_fds(self):
        for open_fd in self.open_fds:
                open_fd.close()
