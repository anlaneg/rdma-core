# SPDX-License-Identifier: (GPL-2.0 OR Linux-OpenIB)
# Copyright (c) 2019 Mellanox Technologies, Inc. All rights reserved. See COPYING file
# Copyright (c) 2020 Kamal Heib <kamalheib1@gmail.com>, All rights reserved.  See COPYING file
# Copyright 2020-2023 Amazon.com, Inc. or its affiliates. All rights reserved.

"""
Test module for pyverbs' qp module.
"""
import unittest
import random
import errno
import os

from pyverbs.pyverbs_error import PyverbsRDMAError
from pyverbs.qp import QPAttr, QP
from tests.base import PyverbsAPITestCase, RDMATestCase, RCResources
import pyverbs.utils as pu
import pyverbs.device as d
from pyverbs.libibverbs_enums import ibv_qp_type, ibv_qp_state, ibv_qp_attr_mask, ibv_node_type, \
    ibv_wr_opcode, ibv_query_qp_data_in_order_flags, ibv_query_qp_data_in_order_caps
from pyverbs.pd import PD
from pyverbs.cq import CQ
import tests.utils as u


class QPTest(PyverbsAPITestCase):
    """
    Test various functionalities of the QP class.
    """

    def create_qp(self, creator, qp_init_attr, is_ex, with_attr, port_num):
        """
        Auxiliary function to create QP object.
        """
        try:
            qp_attr = (None, QPAttr(port_num=port_num))[with_attr]
            return QP(creator, qp_init_attr, qp_attr)
        except PyverbsRDMAError as ex:
            if ex.error_code == errno.EOPNOTSUPP:
                with_str = ('without', 'with')[with_attr] + ('', ' extended')[is_ex]
                qp_type_str = pu.qp_type_to_str(qp_init_attr.qp_type)
                raise unittest.SkipTest(f'Create {qp_type_str} QP {with_str} attrs is not supported')
            raise ex

    def create_qp_common_test(self, qp_type, qp_state, is_ex, with_attr, qp_attr_edit_callback=None):
        """
        Common function used by create QP tests.
        """
        with PD(self.ctx) as pd:
            with CQ(self.ctx, 100, None, None, 0) as cq:
                if qp_type == ibv_qp_type.IBV_QPT_RAW_PACKET:
                    if not (u.is_eth(self.ctx, self.ib_port) and u.is_root()):
                        raise unittest.SkipTest('To Create RAW QP must be done by root on Ethernet link layer')

                if is_ex:
                    qia = get_qp_init_attr_ex(cq, pd, self.attr, self.attr_ex, qp_type)
                    creator = self.ctx
                else:
                    qia = u.get_qp_init_attr(cq, self.attr)
                    qia.qp_type = qp_type
                    creator = pd

                if qp_attr_edit_callback:
                    qia = qp_attr_edit_callback(qia)

                qp = self.create_qp(creator, qia, is_ex, with_attr, self.ib_port)

                qp_type_str = pu.qp_type_to_str(qp_type)
                qp_state_str = pu.qp_state_to_str(qp_state)
                assert qp.qp_state == qp_state , f'{qp_type_str} QP should have been in {qp_state_str}'

    def test_create_rc_qp_no_attr(self):
        """
        Test RC QP creation via ibv_create_qp without a QPAttr object provided.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_RC, ibv_qp_state.IBV_QPS_RESET, False, False)

    def test_create_uc_qp_no_attr(self):
        """
        Test UC QP creation via ibv_create_qp without a QPAttr object provided.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_UC, ibv_qp_state.IBV_QPS_RESET, False, False)

    def test_create_ud_qp_no_attr(self):
        """
        Test UD QP creation via ibv_create_qp without a QPAttr object provided.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_UD, ibv_qp_state.IBV_QPS_RESET, False, False)

    def test_create_raw_qp_no_attr(self):
        """
        Test RAW Packet QP creation via ibv_create_qp without a QPAttr object
        provided.
        Raw Packet is skipped for non-root users / Infiniband link layer.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_RAW_PACKET, ibv_qp_state.IBV_QPS_RESET, False, False)

    def test_create_rc_qp_with_attr(self):
        """
        Test RC QP creation via ibv_create_qp with a QPAttr object provided.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_RC, ibv_qp_state.IBV_QPS_INIT, False, True)

    def test_create_uc_qp_with_attr(self):
        """
        Test UC QP creation via ibv_create_qp with a QPAttr object provided.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_UC, ibv_qp_state.IBV_QPS_INIT, False, True)

    def test_create_ud_qp_with_attr(self):
        """
        Test UD QP creation via ibv_create_qp with a QPAttr object provided.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_UD, ibv_qp_state.IBV_QPS_RTS, False, True)

    def test_create_raw_qp_with_attr(self):
        """
        Test RAW Packet QP creation via ibv_create_qp with a QPAttr object
        provided.
        Raw Packet is skipped for non-root users / Infiniband link layer.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_RAW_PACKET, ibv_qp_state.IBV_QPS_RTS, False, True)

    def test_create_rc_qp_ex_no_attr(self):
        """
        Test RC QP creation via ibv_create_qp_ex without a QPAttr object
        provided.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_RC, ibv_qp_state.IBV_QPS_RESET, True, False)

    def test_create_uc_qp_ex_no_attr(self):
        """
        Test UC QP creation via ibv_create_qp_ex without a QPAttr object
        provided.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_UC, ibv_qp_state.IBV_QPS_RESET, True, False)

    def test_create_ud_qp_ex_no_attr(self):
        """
        Test UD QP creation via ibv_create_qp_ex without a QPAttr object
        provided.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_UD, ibv_qp_state.IBV_QPS_RESET, True, False)

    def test_create_raw_qp_ex_no_attr(self):
        """
        Test Raw Packet QP creation via ibv_create_qp_ex without a QPAttr object
        provided.
        Raw Packet is skipped for non-root users / Infiniband link layer.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_RAW_PACKET, ibv_qp_state.IBV_QPS_RESET, True, False)

    def test_create_rc_qp_ex_with_attr(self):
        """
        Test RC QP creation via ibv_create_qp_ex with a QPAttr object provided.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_RC, ibv_qp_state.IBV_QPS_INIT, True, True)

    def test_create_uc_qp_ex_with_attr(self):
        """
        Test UC QP creation via ibv_create_qp_ex with a QPAttr object provided.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_UC, ibv_qp_state.IBV_QPS_INIT, True, True)

    def test_create_ud_qp_ex_with_attr(self):
        """
        Test UD QP creation via ibv_create_qp_ex with a QPAttr object provided.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_UD, ibv_qp_state.IBV_QPS_RTS, True, True)

    def test_create_raw_qp_ex_with_attr(self):
        """
        Test Raw Packet QP creation via ibv_create_qp_ex with a QPAttr object
        provided.
        Raw Packet is skipped for non-root users / Infiniband link layer.
        """
        self.create_qp_common_test(ibv_qp_type.IBV_QPT_RAW_PACKET, ibv_qp_state.IBV_QPS_RTS, True, True)

    def qp_attr_edit_max_send_wr_callback(self, qp_init_attr):
        qp_init_attr.max_send_wr = 0xffffffff # max_uint32
        return qp_init_attr

    def qp_attr_edit_max_send_sge_callback(self, qp_init_attr):
        qp_init_attr.max_send_sge = 0xffff # max_uint16
        return qp_init_attr

    def qp_attr_edit_max_recv_sge_callback(self, qp_init_attr):
        qp_init_attr.max_recv_sge = 0xffff # max_uint16
        return qp_init_attr

    def qp_attr_edit_max_recv_wr_callback(self, qp_init_attr):
        qp_init_attr.max_recv_wr = 0xffffffff # max_uint32
        return qp_init_attr

    def test_create_raw_qp_ex_with_illegal_caps_max_send_wr(self):
        """
        Test Raw Packet QP creation via ibv_create_qp_ex with a QPAttr object with illegal max_send_wr.
        """
        dev_attr = self.ctx.query_device()
        if dev_attr.max_qp_wr < 0xffffffff:
            with self.assertRaises(PyverbsRDMAError) as ex:
                self.create_qp_common_test(ibv_qp_type.IBV_QPT_UD, ibv_qp_state.IBV_QPS_RTS, False, True,
                                        qp_attr_edit_callback=self.qp_attr_edit_max_send_wr_callback)
            self.assertNotEqual(ex.exception.error_code, 0)

    def test_create_raw_qp_ex_with_illegal_caps_max_send_sge(self):
        """
        Test Raw Packet QP creation via ibv_create_qp_ex with a QPAttr object with illegal max_send_sge.
        """
        dev_attr = self.ctx.query_device()
        if dev_attr.max_sge < 0xffff:
            with self.assertRaises(PyverbsRDMAError) as ex:
                self.create_qp_common_test(ibv_qp_type.IBV_QPT_UD, ibv_qp_state.IBV_QPS_RTS, False, True,
                                        qp_attr_edit_callback=self.qp_attr_edit_max_send_sge_callback)
            self.assertNotEqual(ex.exception.error_code, 0)

    def test_create_raw_qp_ex_with_illegal_caps_max_recv_sge(self):
        """
        Test Raw Packet QP creation via ibv_create_qp_ex with a QPAttr object with illegal max_recv_sge.
        """
        dev_attr = self.ctx.query_device()
        if dev_attr.max_sge < 0xffff:
            with self.assertRaises(PyverbsRDMAError) as ex:
                self.create_qp_common_test(ibv_qp_type.IBV_QPT_UD, ibv_qp_state.IBV_QPS_RTS, False, True,
                                        qp_attr_edit_callback=self.qp_attr_edit_max_recv_sge_callback)
            self.assertNotEqual(ex.exception.error_code, 0)

    def test_create_raw_qp_ex_with_illegal_caps_max_recv_wr(self):
        """
        Test Raw Packet QP creation via ibv_create_qp_ex with a QPAttr object with illegal max_recv_wr.
        """
        dev_attr = self.ctx.query_device()
        if dev_attr.max_qp_wr < 0xffffffff:
            with self.assertRaises(PyverbsRDMAError) as ex:
                self.create_qp_common_test(ibv_qp_type.IBV_QPT_UD, ibv_qp_state.IBV_QPS_RTS, False, True,
                                        qp_attr_edit_callback=self.qp_attr_edit_max_recv_wr_callback)
            self.assertNotEqual(ex.exception.error_code, 0)

    def verify_qp_attrs(self, orig_cap, state, init_attr, attr):
        self.assertEqual(state, attr.qp_state)
        self.assertLessEqual(orig_cap.max_send_wr, init_attr.cap.max_send_wr)
        self.assertLessEqual(orig_cap.max_recv_wr, init_attr.cap.max_recv_wr)
        self.assertLessEqual(orig_cap.max_send_sge, init_attr.cap.max_send_sge)
        self.assertLessEqual(orig_cap.max_recv_sge, init_attr.cap.max_recv_sge)
        self.assertLessEqual(orig_cap.max_inline_data, init_attr.cap.max_inline_data)

    def get_node_type(self):
        for dev in d.get_device_list():
            if dev.name.decode() == self.ctx.name:
                return dev.node_type

    def query_qp_common_test(self, qp_type):
        with PD(self.ctx) as pd:
            with CQ(self.ctx, 100, None, None, 0) as cq:
                if qp_type == ibv_qp_type.IBV_QPT_RAW_PACKET:
                    if not (u.is_eth(self.ctx, self.ib_port) and u.is_root()):
                        raise unittest.SkipTest('To Create RAW QP must be done by root on Ethernet link layer')

                # Legacy QP
                qia = u.get_qp_init_attr(cq, self.attr)
                qia.qp_type = qp_type
                caps = qia.cap
                qp = self.create_qp(pd, qia, False, False, self.ib_port)
                qp_attr, qp_init_attr = qp.query(ibv_qp_attr_mask.IBV_QP_STATE | ibv_qp_attr_mask.IBV_QP_CAP)
                if self.get_node_type() == ibv_node_type.IBV_NODE_RNIC:
                    self.verify_qp_attrs(caps, ibv_qp_state.IBV_QPS_INIT, qp_init_attr, qp_attr)
                else:
                    self.verify_qp_attrs(caps, ibv_qp_state.IBV_QPS_RESET, qp_init_attr, qp_attr)

                # Extended QP
                qia = get_qp_init_attr_ex(cq, pd, self.attr, self.attr_ex, qp_type)
                caps = qia.cap # Save them to verify values later
                qp = self.create_qp(self.ctx, qia, True, False, self.ib_port)
                qp_attr, qp_init_attr = qp.query(ibv_qp_attr_mask.IBV_QP_STATE | ibv_qp_attr_mask.IBV_QP_CAP)
                if self.get_node_type() == ibv_node_type.IBV_NODE_RNIC:
                    self.verify_qp_attrs(caps, ibv_qp_state.IBV_QPS_INIT, qp_init_attr, qp_attr)
                else:
                    self.verify_qp_attrs(caps, ibv_qp_state.IBV_QPS_RESET, qp_init_attr, qp_attr)

    def test_query_rc_qp(self):
        """
        Queries an RC QP after creation. Verifies that its properties are as
        expected.
        """
        self.query_qp_common_test(ibv_qp_type.IBV_QPT_RC)

    def test_query_uc_qp(self):
        """
        Queries an UC QP after creation. Verifies that its properties are as
        expected.
        """
        self.query_qp_common_test(ibv_qp_type.IBV_QPT_UC)

    def test_query_ud_qp(self):
        """
        Queries an UD QP after creation. Verifies that its properties are as
        expected.
        """
        self.query_qp_common_test(ibv_qp_type.IBV_QPT_UD)

    def test_query_raw_qp(self):
        """
        Queries an RAW Packet QP after creation. Verifies that its properties
        are as expected.
        Raw Packet is skipped for non-root users / Infiniband link layer.
        """
        self.query_qp_common_test(ibv_qp_type.IBV_QPT_RAW_PACKET)

    def test_query_data_in_order(self):
        """
        Queries an UD QP data in order after moving it to RTS state.
        Verifies that the result from the query is valid.
        """
        with PD(self.ctx) as pd:
            with CQ(self.ctx, 100, None, None, 0) as cq:
                qia = u.get_qp_init_attr(cq, self.attr)
                qia.qp_type = ibv_qp_type.IBV_QPT_UD
                qp = self.create_qp(pd, qia, False, True, self.ib_port)
                is_data_in_order = qp.query_data_in_order(ibv_wr_opcode.IBV_WR_SEND)
                self.assertIn(is_data_in_order, [0, 1], 'Data in order result with flags=0 is not valid')
                is_data_in_order = qp.query_data_in_order(ibv_wr_opcode.IBV_WR_SEND,
                                                          ibv_query_qp_data_in_order_flags.IBV_QUERY_QP_DATA_IN_ORDER_RETURN_CAPS)
                valid_results = [0,
                                ibv_query_qp_data_in_order_caps.IBV_QUERY_QP_DATA_IN_ORDER_ALIGNED_128_BYTES,
                                ibv_query_qp_data_in_order_caps.IBV_QUERY_QP_DATA_IN_ORDER_WHOLE_MSG | \
                                    ibv_query_qp_data_in_order_caps.IBV_QUERY_QP_DATA_IN_ORDER_ALIGNED_128_BYTES]
                self.assertIn(is_data_in_order, valid_results, 'Data in order result with flags=1 is not valid')

    @u.skip_unsupported
    def test_modify_ud_qp(self):
        """
        Queries a UD QP after calling modify(). Verifies that its properties are
        as expected.
        """
        with PD(self.ctx) as pd:
            with CQ(self.ctx, 100, None, None, 0) as cq:
                # Legacy QP
                qia = u.get_qp_init_attr(cq, self.attr)
                qia.qp_type = ibv_qp_type.IBV_QPT_UD
                qp = self.create_qp(pd, qia, False, False, self.ib_port)
                qa = QPAttr()
                qa.qkey = 0x123
                qp.to_init(qa)
                qp_attr, _ = qp.query(ibv_qp_attr_mask.IBV_QP_QKEY)
                assert qp_attr.qkey == qa.qkey, 'Legacy QP, QKey is not as expected'
                qp.to_rtr(qa)
                qa.sq_psn = 0x45
                qp.to_rts(qa)
                qp_attr, _ = qp.query(ibv_qp_attr_mask.IBV_QP_SQ_PSN)
                assert qp_attr.sq_psn == qa.sq_psn, 'Legacy QP, SQ PSN is not as expected'
                qa.qp_state = ibv_qp_state.IBV_QPS_RESET
                qp.modify(qa, ibv_qp_attr_mask.IBV_QP_STATE)
                assert qp.qp_state == ibv_qp_state.IBV_QPS_RESET, 'Legacy QP, QP state is not as expected'
                # Extended QP
                qia = get_qp_init_attr_ex(cq, pd, self.attr, self.attr_ex, ibv_qp_type.IBV_QPT_UD)
                qp = self.create_qp(self.ctx, qia, True, False, self.ib_port)
                qa = QPAttr()
                qa.qkey = 0x123
                qp.to_init(qa)
                qp_attr, _ = qp.query(ibv_qp_attr_mask.IBV_QP_QKEY)
                assert qp_attr.qkey == qa.qkey, 'Extended QP, QKey is not as expected'
                qp.to_rtr(qa)
                qa.sq_psn = 0x45
                qp.to_rts(qa)
                qp_attr, _ = qp.query(ibv_qp_attr_mask.IBV_QP_SQ_PSN)
                assert qp_attr.sq_psn == qa.sq_psn, 'Extended QP, SQ PSN is not as expected'
                qa.qp_state = ibv_qp_state.IBV_QPS_RESET
                qp.modify(qa, ibv_qp_attr_mask.IBV_QP_STATE)
                assert qp.qp_state == ibv_qp_state.IBV_QPS_RESET, 'Extended QP, QP state is not as expected'


class RCQPTest(RDMATestCase):
    """
    Test various functionalities of the RC QP class.
    """
    def test_modify_rc_qp_rd_atomic(self):
        """
        This test verifies that the values of rd_atomic fields are
        at least the requested value.
        """
        self.max_rd_atomic = 12
        self.max_dest_rd_atomic = 12

        self.create_players(RCResources, max_rd_atomic=self.max_rd_atomic,
                            max_dest_rd_atomic=self.max_dest_rd_atomic)

        qp_attr, _ = self.server.qp.query(ibv_qp_attr_mask.IBV_QP_MAX_QP_RD_ATOMIC | \
                                          ibv_qp_attr_mask.IBV_QP_MAX_DEST_RD_ATOMIC)

        self.assertGreaterEqual(qp_attr.max_rd_atomic, self.max_rd_atomic,
                                'Max RD Atomic value is less than requested.')
        self.assertGreaterEqual(qp_attr.max_dest_rd_atomic, self.max_dest_rd_atomic,
                                'Max Dest RD Atomic is less than requested.')


def get_qp_init_attr_ex(cq, pd, attr, attr_ex, qpt):
    """
    Creates a QPInitAttrEx object with a QP type of the provided <qpts> array
    and other random values.
    :param cq: CQ to be used as send and receive CQ
    :param pd: A PD object to use
    :param attr: Device attributes for capability checks
    :param attr_ex: Extended device attributes for capability checks
    :param qpt: QP type
    :return: An initialized QPInitAttrEx object
    """
    qia = u.random_qp_init_attr_ex(attr_ex, attr, qpt)
    qia.send_cq = cq
    qia.recv_cq = cq
    qia.pd = pd  # Only XRCD can be created without a PD
    return qia
