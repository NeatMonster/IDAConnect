# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program. If not, see <http://www.gnu.org/licenses/>.
# import ctypes

import ida_auto
import ida_bytes
import ida_enum
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_idp
import ida_kernwin
import ida_nalt
import ida_pro
import ida_segment
import ida_struct
import ida_typeinf

from . import events  # noqa: I100,I202
from .events import Event  # noqa: I201


class Hooks(object):
    """
    This is a common class for all client hooks. It adds an utility method to
    send an user event to all other clients through the server.
    """

    def __init__(self, plugin):
        self._plugin = plugin

    def _send_packet(self, event):
        """Sends a packet to the server."""
        # Check if it comes from the auto-analyzer
        if ida_auto.get_auto_state() == ida_auto.AU_NONE:
            self._plugin.network.send_packet(event)
        else:
            self._plugin.logger.debug("Ignoring a packet")


class IDBHooks(Hooks, ida_idp.IDB_Hooks):
    def __init__(self, plugin):
        ida_idp.IDB_Hooks.__init__(self)
        Hooks.__init__(self, plugin)
        self.last_local_type = None

    def make_code(self, insn):
        self._send_packet(evt.MakeCodeEvent(insn.ea))
        return 0

    def make_data(self, ea, flags, tid, size):
        self._send_packet(evt.MakeDataEvent(ea, flags, size, tid))
        return 0

    def renamed(self, ea, new_name, local_name):
        self._send_packet(evt.RenamedEvent(ea, new_name, local_name))
        return 0

    def func_added(self, func):
        self._send_packet(evt.FuncAddedEvent(func.start_ea, func.end_ea))
        return 0

    def deleting_func(self, func):
        self._send_packet(evt.DeletingFuncEvent(func.start_ea))
        return 0

    def set_func_start(self, func, new_start):
        self._send_packet(evt.SetFuncStartEvent(func.start_ea, new_start))
        return 0

    def set_func_end(self, func, new_end):
        self._send_packet(evt.SetFuncEndEvent(func.start_ea, new_end))
        return 0

    def func_tail_appended(self, func, tail):
        self._send_packet(
            evt.FuncTailAppendedEvent(
                func.start_ea, tail.start_ea, tail.end_ea
            )
        )
        return 0

    def func_tail_deleted(self, func, tail_ea):
        self._send_packet(evt.FuncTailDeletedEvent(func.start_ea, tail_ea))
        return 0

    def tail_owner_changed(self, tail, owner_func, old_owner):
        self._send_packet(evt.TailOwnerChangedEvent(tail.start_ea, owner_func))
        return 0

    def cmt_changed(self, ea, repeatable_cmt):
        cmt = ida_bytes.get_cmt(ea, repeatable_cmt)
        cmt = "" if not cmt else cmt
        self._send_packet(evt.CmtChangedEvent(ea, cmt, repeatable_cmt))
        return 0

    def range_cmt_changed(self, kind, a, cmt, repeatable):
        self._send_packet(evt.RangeCmtChangedEvent(kind, a, cmt, repeatable))
        return 0

    def extra_cmt_changed(self, ea, line_idx, cmt):
        self._send_packet(evt.ExtraCmtChangedEvent(ea, line_idx, cmt))
        return 0

    def ti_changed(self, ea, type, fname):
        type = ida_typeinf.idc_get_type_raw(ea)
        self._send_packet(evt.TiChangedEvent(ea, type))
        return 0

    # def local_types_changed(self):
    #     from .core import Core

    #     dll = Core.get_ida_dll()

    #     get_idati = dll.get_idati
    #     get_idati.argtypes = []
    #     get_idati.restype = ctypes.c_void_p

    #     get_numbered_type = dll.get_numbered_type
    #     get_numbered_type.argtypes = [
    #         ctypes.c_void_p,
    #         ctypes.c_uint32,
    #         ctypes.POINTER(ctypes.c_char_p),
    #         ctypes.POINTER(ctypes.c_char_p),
    #         ctypes.POINTER(ctypes.c_char_p),
    #         ctypes.POINTER(ctypes.c_char_p),
    #         ctypes.POINTER(ctypes.c_int),
    #     ]
    #     get_numbered_type.restype = ctypes.c_bool

    #     local_types = []
    #     py_ti = ida_typeinf.get_idati()
    #     for py_ord in range(1, ida_typeinf.get_ordinal_qty(py_ti)):
    #         name = ida_typeinf.get_numbered_type_name(py_ti, py_ord)

    #         ti = get_idati()
    #         ordinal = ctypes.c_uint32(py_ord)
    #         type = ctypes.c_char_p()
    #         fields = ctypes.c_char_p()
    #         cmt = ctypes.c_char_p()
    #         fieldcmts = ctypes.c_char_p()
    #         sclass = ctypes.c_int()
    #         get_numbered_type(
    #             ti,
    #             ordinal,
    #             ctypes.pointer(type),
    #             ctypes.pointer(fields),
    #             ctypes.pointer(cmt),
    #             ctypes.pointer(fieldcmts),
    #             ctypes.pointer(sclass),
    #         )
    #         local_types.append(
    #             (
    #                 py_ord,
    #                 name,
    #                 type.value,
    #                 fields.value,
    #                 cmt.value,
    #                 fieldcmts.value,
    #                 sclass.value,
    #             )
    #         )
    #     self._send_packet(evt.LocalTypesChangedEvent(local_types))
    #     return 0

    def op_type_changed(self, ea, n):
        def gather_enum_info(ea, n):
            id = ida_bytes.get_enum_id(ea, n)[0]
            serial = ida_enum.get_enum_idx(id)
            return id, serial

        extra = {}
        mask = ida_bytes.MS_0TYPE if not n else ida_bytes.MS_1TYPE
        flags = ida_bytes.get_full_flags(ea) & mask

        def is_flag(type):
            return flags == mask & type

        if is_flag(ida_bytes.hex_flag()):
            op = "hex"
        elif is_flag(ida_bytes.dec_flag()):
            op = "dec"
        elif is_flag(ida_bytes.char_flag()):
            op = "chr"
        elif is_flag(ida_bytes.bin_flag()):
            op = "bin"
        elif is_flag(ida_bytes.oct_flag()):
            op = "oct"
        elif is_flag(ida_bytes.enum_flag()):
            op = "enum"
            id, serial = gather_enum_info(ea, n)
            ename = ida_enum.get_enum_name(id)
            extra["ename"] = Event.decode(ename)
            extra["serial"] = serial
        elif is_flag(flags & ida_bytes.stroff_flag()):
            op = "struct"
            path = ida_pro.tid_array(1)
            delta = ida_pro.sval_pointer()
            path_len = ida_bytes.get_stroff_path(
                path.cast(), delta.cast(), ea, n
            )
            spath = []
            for i in range(path_len):
                sname = ida_struct.get_struc_name(path[i])
                spath.append(Event.decode(sname))
            extra["delta"] = delta.value()
            extra["spath"] = spath
        elif is_flag(ida_bytes.stkvar_flag()):
            op = "stkvar"
        # FIXME: No hooks are called when inverting sign
        # elif ida_bytes.is_invsign(ea, flags, n):
        #     op = 'invert_sign'
        else:
            return 0  # FIXME: Find a better way to do this
        self._send_packet(evt.OpTypeChangedEvent(ea, n, op, extra))
        return 0

    def enum_created(self, enum):
        name = ida_enum.get_enum_name(enum)
        self._send_packet(evt.EnumCreatedEvent(enum, name))
        return 0

    def deleting_enum(self, id):
        self._send_packet(evt.EnumDeletedEvent(ida_enum.get_enum_name(id)))
        return 0

    def renaming_enum(self, id, is_enum, newname):
        if is_enum:
            oldname = ida_enum.get_enum_name(id)
        else:
            oldname = ida_enum.get_enum_member_name(id)
        self._send_packet(evt.EnumRenamedEvent(oldname, newname, is_enum))
        return 0

    def enum_bf_changed(self, id):
        bf_flag = 1 if ida_enum.is_bf(id) else 0
        ename = ida_enum.get_enum_name(id)
        self._send_packet(evt.EnumBfChangedEvent(ename, bf_flag))
        return 0

    def enum_cmt_changed(self, tid, repeatable_cmt):
        cmt = ida_enum.get_enum_cmt(tid, repeatable_cmt)
        emname = ida_enum.get_enum_name(tid)
        self._send_packet(evt.EnumCmtChangedEvent(emname, cmt, repeatable_cmt))
        return 0

    def enum_member_created(self, id, cid):
        ename = ida_enum.get_enum_name(id)
        name = ida_enum.get_enum_member_name(cid)
        value = ida_enum.get_enum_member_value(cid)
        bmask = ida_enum.get_enum_member_bmask(cid)
        self._send_packet(
            evt.EnumMemberCreatedEvent(ename, name, value, bmask)
        )
        return 0

    def deleting_enum_member(self, id, cid):
        ename = ida_enum.get_enum_name(id)
        value = ida_enum.get_enum_member_value(cid)
        serial = ida_enum.get_enum_member_serial(cid)
        bmask = ida_enum.get_enum_member_bmask(cid)
        self._send_packet(
            evt.EnumMemberDeletedEvent(ename, value, serial, bmask)
        )
        return 0

    def struc_created(self, tid):
        name = ida_struct.get_struc_name(tid)
        is_union = ida_struct.is_union(tid)
        self._send_packet(evt.StrucCreatedEvent(tid, name, is_union))
        return 0

    def deleting_struc(self, sptr):
        sname = ida_struct.get_struc_name(sptr.id)
        self._send_packet(evt.StrucDeletedEvent(sname))
        return 0

    def renaming_struc(self, id, oldname, newname):
        self._send_packet(evt.StrucRenamedEvent(oldname, newname))
        return 0

    def struc_member_created(self, sptr, mptr):
        extra = {}
        sname = ida_struct.get_struc_name(sptr.id)
        fieldname = ida_struct.get_member_name(mptr.id)
        offset = 0 if mptr.unimem() else mptr.soff
        flag = mptr.flag
        nbytes = mptr.eoff if mptr.unimem() else mptr.eoff - mptr.soff
        mt = ida_nalt.opinfo_t()
        is_not_data = ida_struct.retrieve_member_info(mt, mptr)
        if is_not_data:
            if flag & ida_bytes.off_flag():
                extra["target"] = mt.ri.target
                extra["base"] = mt.ri.base
                extra["tdelta"] = mt.ri.tdelta
                extra["flags"] = mt.ri.flags
                self._send_packet(
                    evt.StrucMemberCreatedEvent(
                        sname, fieldname, offset, flag, nbytes, extra
                    )
                )
            # Is it really possible to create an enum?
            elif flag & ida_bytes.enum_flag():
                extra["serial"] = mt.ec.serial
                self._send_packet(
                    evt.StrucMemberCreatedEvent(
                        sname, fieldname, offset, flag, nbytes, extra
                    )
                )
            elif flag & ida_bytes.stru_flag():
                extra["id"] = mt.tid
                if flag & ida_bytes.strlit_flag():
                    extra["strtype"] = mt.strtype
                self._send_packet(
                    evt.StrucMemberCreatedEvent(
                        sname, fieldname, offset, flag, nbytes, extra
                    )
                )
        else:
            self._send_packet(
                evt.StrucMemberCreatedEvent(
                    sname, fieldname, offset, flag, nbytes, extra
                )
            )
        return 0

    def struc_member_deleted(self, sptr, off1, off2):
        sname = ida_struct.get_struc_name(sptr.id)
        self._send_packet(evt.StrucMemberDeletedEvent(sname, off2))
        return 0

    def renaming_struc_member(self, sptr, mptr, newname):
        sname = ida_struct.get_struc_name(sptr.id)
        offset = mptr.soff
        self._send_packet(evt.StrucMemberRenamedEvent(sname, offset, newname))
        return 0

    def struc_cmt_changed(self, id, repeatable_cmt):
        fullname = ida_struct.get_struc_name(id)
        if "." in fullname:
            sname, smname = fullname.split(".", 1)
        else:
            sname = fullname
            smname = ""
        cmt = ida_struct.get_struc_cmt(id, repeatable_cmt)
        self._send_packet(
            evt.StrucCmtChangedEvent(sname, smname, cmt, repeatable_cmt)
        )
        return 0

    def struc_member_changed(self, sptr, mptr):
        extra = {}

        sname = ida_struct.get_struc_name(sptr.id)
        soff = 0 if mptr.unimem() else mptr.soff
        flag = mptr.flag
        mt = ida_nalt.opinfo_t()
        is_not_data = ida_struct.retrieve_member_info(mt, mptr)
        if is_not_data:
            if flag & ida_bytes.off_flag():
                extra["target"] = mt.ri.target
                extra["base"] = mt.ri.base
                extra["tdelta"] = mt.ri.tdelta
                extra["flags"] = mt.ri.flags
                self._send_packet(
                    evt.StrucMemberChangedEvent(
                        sname, soff, mptr.eoff, flag, extra
                    )
                )
            elif flag & ida_bytes.enum_flag():
                extra["serial"] = mt.ec.serial
                self._send_packet(
                    evt.StrucMemberChangedEvent(
                        sname, soff, mptr.eoff, flag, extra
                    )
                )
            elif flag & ida_bytes.stru_flag():
                extra["id"] = mt.tid
                if flag & ida_bytes.strlit_flag():
                    extra["strtype"] = mt.strtype
                self._send_packet(
                    evt.StrucMemberChangedEvent(
                        sname, soff, mptr.eoff, flag, extra
                    )
                )
        else:
            self._send_packet(
                evt.StrucMemberChangedEvent(
                    sname, soff, mptr.eoff, flag, extra
                )
            )
        return 0

    def expanding_struc(self, sptr, offset, delta):
        sname = ida_struct.get_struc_name(sptr.id)
        self._send_packet(evt.ExpandingStrucEvent(sname, offset, delta))
        return 0

    def segm_added(self, s):
        self._send_packet(
            evt.SegmAddedEvent(
                ida_segment.get_segm_name(s),
                ida_segment.get_segm_class(s),
                s.start_ea,
                s.end_ea,
                s.orgbase,
                s.align,
                s.comb,
                s.perm,
                s.bitness,
                s.flags,
            )
        )
        return 0

    # This hook lack of disable addresses option
    def segm_deleted(self, start_ea, end_ea):
        self._send_packet(evt.SegmDeletedEvent(start_ea))
        return 0

    def segm_start_changed(self, s, oldstart):
        self._send_packet(evt.SegmStartChangedEvent(s.start_ea, oldstart))
        return 0

    def segm_end_changed(self, s, oldend):
        self._send_packet(evt.SegmEndChangedEvent(s.end_ea, s.start_ea))
        return 0

    def segm_name_changed(self, s, name):
        self._send_packet(evt.SegmNameChangedEvent(s.start_ea, name))
        return 0

    def segm_class_changed(self, s, sclass):
        self._send_packet(evt.SegmClassChangedEvent(s.start_ea, sclass))
        return 0

    def segm_attrs_updated(self, s):
        self._send_packet(
            evt.SegmAttrsUpdatedEvent(s.start_ea, s.perm, s.bitness)
        )
        return 0

    def segm_moved(self, from_ea, to_ea, size, changed_netmap):
        self._send_packet(evt.SegmMoved(from_ea, to_ea, changed_netmap))
        return 0

    def byte_patched(self, ea, old_value):
        self._send_packet(
            evt.BytePatchedEvent(ea, ida_bytes.get_wide_byte(ea))
        )
        return 0

    def sgr_changed(self, start_ea, end_ea, regnum, value, old_value, tag):
        # FIXME: sgr_changed is not triggered when a segment register is
        # being deleted by the user, so we need to sent the complete list
        sreg_ranges = evt.SgrChanged.get_sreg_ranges(regnum)
        self._send_packet(evt.SgrChanged(regnum, sreg_ranges))
        return 0


class IDPHooks(Hooks, ida_idp.IDP_Hooks):
    def __init__(self, plugin):
        ida_idp.IDP_Hooks.__init__(self)
        Hooks.__init__(self, plugin)

    def ev_undefine(self, ea):
        self._send_packet(evt.UndefinedEvent(ea))
        return ida_idp.IDP_Hooks.ev_undefine(self, ea)

    def ev_adjust_argloc(self, *args):
        return ida_idp.IDP_Hooks.ev_adjust_argloc(self, *args)

    # def ev_gen_regvar_def(self, outctx, v):
    #    self._send_packet(
    #        evt.GenRegvarDefEvent(outctx.bin_ea, v.canon, v.user, v.cmt)
    #    )
    #    return ida_idp.IDP_Hooks.ev_gen_regvar_def(self, outctx, v)


class HexRaysHooks(Hooks):
    def __init__(self, plugin):
        super(HexRaysHooks, self).__init__(plugin)
        self._available = None
        self._installed = False
        self._func_ea = ida_idaapi.BADADDR
        self._labels = {}
        self._cmts = {}
        self._iflags = {}
        self._lvar_settings = {}
        self._numforms = {}

    def hook(self):
        if self._available is None:
            if not ida_hexrays.init_hexrays_plugin():
                self._plugin.logger.info("Hex-Rays SDK is not available")
                self._available = False
            else:
                ida_hexrays.install_hexrays_callback(self._hxe_callback)
                self._available = True

        if self._available:
            self._installed = True

    def unhook(self):
        if self._available:
            self._installed = False

    def _hxe_callback(self, event, *_):
        if not self._installed:
            return 0

        if event == ida_hexrays.hxe_func_printed:
            ea = ida_kernwin.get_screen_ea()
            func = ida_funcs.get_func(ea)
            if func is None:
                return

            if self._func_ea != func.start_ea:
                self._func_ea = func.start_ea
                self._labels = HexRaysHooks._get_user_labels(self._func_ea)
                self._cmts = HexRaysHooks._get_user_cmts(self._func_ea)
                self._iflags = HexRaysHooks._get_user_iflags(self._func_ea)
                self._lvar_settings = HexRaysHooks._get_user_lvar_settings(
                    self._func_ea
                )
                self._numforms = HexRaysHooks._get_user_numforms(self._func_ea)
            self._send_user_labels(func.start_ea)
            self._send_user_cmts(func.start_ea)
            self._send_user_iflags(func.start_ea)
            self._send_user_lvar_settings(func.start_ea)
            self._send_user_numforms(func.start_ea)
        return 0

    @staticmethod
    def _get_user_labels(ea):
        user_labels = ida_hexrays.restore_user_labels(ea)
        if user_labels is None:
            user_labels = ida_hexrays.user_labels_new()
        labels = []
        it = ida_hexrays.user_labels_begin(user_labels)
        while it != ida_hexrays.user_labels_end(user_labels):
            org_label = ida_hexrays.user_labels_first(it)
            name = ida_hexrays.user_labels_second(it)
            labels.append((org_label, Event.decode(name)))
            it = ida_hexrays.user_labels_next(it)
        ida_hexrays.user_labels_free(user_labels)
        return labels

    def _send_user_labels(self, ea):
        labels = HexRaysHooks._get_user_labels(ea)
        if labels != self._labels:
            self._send_packet(evt.UserLabelsEvent(ea, labels))
            self._labels = labels

    @staticmethod
    def _get_user_cmts(ea):
        user_cmts = ida_hexrays.restore_user_cmts(ea)
        if user_cmts is None:
            user_cmts = ida_hexrays.user_cmts_new()
        cmts = []
        it = ida_hexrays.user_cmts_begin(user_cmts)
        while it != ida_hexrays.user_cmts_end(user_cmts):
            tl = ida_hexrays.user_cmts_first(it)
            cmt = ida_hexrays.user_cmts_second(it)
            cmts.append(((tl.ea, tl.itp), Event.decode(str(cmt))))
            it = ida_hexrays.user_cmts_next(it)
        ida_hexrays.user_cmts_free(user_cmts)
        return cmts

    def _send_user_cmts(self, ea):
        cmts = HexRaysHooks._get_user_cmts(ea)
        if cmts != self._cmts:
            self._send_packet(evt.UserCmtsEvent(ea, cmts))
            self._cmts = cmts

    @staticmethod
    def _get_user_iflags(ea):
        user_iflags = ida_hexrays.restore_user_iflags(ea)
        if user_iflags is None:
            user_iflags = ida_hexrays.user_iflags_new()
        iflags = []
        it = ida_hexrays.user_iflags_begin(user_iflags)
        while it != ida_hexrays.user_iflags_end(user_iflags):
            cl = ida_hexrays.user_iflags_first(it)
            f = ida_hexrays.user_iflags_second(it)

            # FIXME: Temporary while Hex-Rays update their API
            def read_type_sign(obj):
                import ctypes
                import struct

                buf = ctypes.string_at(id(obj), 4)
                return struct.unpack("I", buf)[0]

            f = read_type_sign(f)
            iflags.append(((cl.ea, cl.op), f))
            it = ida_hexrays.user_iflags_next(it)
        ida_hexrays.user_iflags_free(user_iflags)
        return iflags

    def _send_user_iflags(self, ea):
        iflags = HexRaysHooks._get_user_iflags(ea)
        if iflags != self._iflags:
            self._send_packet(evt.UserIflagsEvent(ea, iflags))
            self._iflags = iflags

    @staticmethod
    def _get_user_lvar_settings(ea):
        dct = {}
        lvinf = ida_hexrays.lvar_uservec_t()
        if ida_hexrays.restore_user_lvar_settings(lvinf, ea):
            dct["lvvec"] = []
            for lv in lvinf.lvvec:
                dct["lvvec"].append(HexRaysHooks._get_lvar_saved_info(lv))
            if hasattr(lvinf, "sizes"):
                dct["sizes"] = list(lvinf.sizes)
            dct["lmaps"] = []
            it = ida_hexrays.lvar_mapping_begin(lvinf.lmaps)
            while it != ida_hexrays.lvar_mapping_end(lvinf.lmaps):
                key = ida_hexrays.lvar_mapping_first(it)
                key = HexRaysHooks._get_lvar_locator(key)
                val = ida_hexrays.lvar_mapping_second(it)
                val = HexRaysHooks._get_lvar_locator(val)
                dct["lmaps"].append((key, val))
                it = ida_hexrays.lvar_mapping_next(it)
            dct["stkoff_delta"] = lvinf.stkoff_delta
            dct["ulv_flags"] = lvinf.ulv_flags
        return dct

    @staticmethod
    def _get_lvar_saved_info(lv):
        return {
            "ll": HexRaysHooks._get_lvar_locator(lv.ll),
            "name": Event.decode(lv.name),
            "type": HexRaysHooks._get_tinfo(lv.type),
            "cmt": Event.decode(lv.cmt),
            "flags": lv.flags,
        }

    @staticmethod
    def _get_tinfo(type):
        if type.empty():
            return None, None, None

        type, fields, fldcmts = type.serialize()
        type = Event.decode_bytes(type)
        fields = Event.decode_bytes(fields)
        fldcmts = Event.decode_bytes(fldcmts)
        return type, fields, fldcmts

    @staticmethod
    def _get_lvar_locator(ll):
        return {
            "location": HexRaysHooks._get_vdloc(ll.location),
            "defea": ll.defea,
        }

    @staticmethod
    def _get_vdloc(location):
        return {
            "atype": location.atype(),
            "reg1": location.reg1(),
            "reg2": location.reg2(),
            "stkoff": location.stkoff(),
            "ea": location.get_ea(),
        }

    def _send_user_lvar_settings(self, ea):
        lvar_settings = HexRaysHooks._get_user_lvar_settings(ea)
        if lvar_settings != self._lvar_settings:
            self._send_packet(evt.UserLvarSettingsEvent(ea, lvar_settings))
            self._lvar_settings = lvar_settings

    @staticmethod
    def _get_user_numforms(ea):
        user_numforms = ida_hexrays.restore_user_numforms(ea)
        if user_numforms is None:
            user_numforms = ida_hexrays.user_numforms_new()
        numforms = []
        it = ida_hexrays.user_numforms_begin(user_numforms)
        while it != ida_hexrays.user_numforms_end(user_numforms):
            ol = ida_hexrays.user_numforms_first(it)
            nf = ida_hexrays.user_numforms_second(it)
            numforms.append(
                (
                    HexRaysHooks._get_operand_locator(ol),
                    HexRaysHooks._get_number_format(nf),
                )
            )
            it = ida_hexrays.user_numforms_next(it)
        ida_hexrays.user_numforms_free(user_numforms)
        return numforms

    @staticmethod
    def _get_operand_locator(ol):
        return {"ea": ol.ea, "opnum": ol.opnum}

    @staticmethod
    def _get_number_format(nf):
        return {
            "flags": nf.flags,
            "opnum": nf.opnum,
            "props": nf.props,
            "serial": nf.serial,
            "org_nbytes": nf.org_nbytes,
            "type_name": nf.type_name,
        }

    def _send_user_numforms(self, ea):
        numforms = HexRaysHooks._get_user_numforms(ea)
        if numforms != self._numforms:
            self._send_packet(evt.UserNumformsEvent(ea, numforms))
            self._numforms = numforms
