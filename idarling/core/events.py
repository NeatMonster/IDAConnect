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
import ctypes
import sys

import ida_bytes
import ida_enum
import ida_funcs
import ida_hexrays
import ida_kernwin
import ida_lines
import ida_nalt
import ida_name
import ida_pro
import ida_range
import ida_segment
import ida_segregs
import ida_struct
import ida_typeinf
import ida_ua
import ida_idc

from ..shared.packets import DefaultEvent

if sys.version_info > (3,):
    unicode = str


class Event(DefaultEvent):
    """
    This is a common class for all events that provides utility methods to
    encode/decode strings and raw bytes. Events should also implement __call__
    which is called when the event needs to be replayed into IDA.
    """

    @staticmethod
    def encode(s):
        """Encodes a unicode string into UTF-8 bytes."""
        if isinstance(s, unicode):
            return s.encode("utf-8")
        return s

    @staticmethod
    def encode_bytes(s):
        """Encodes a unicode string into raw bytes."""
        if isinstance(s, unicode):
            return s.encode("raw_unicode_escape")
        return s

    @staticmethod
    def decode(s):
        """Decodes UTF-8 bytes into a unicode string."""
        if not isinstance(s, bytes):
            return s
        return s.decode("utf-8")

    @staticmethod
    def decode_bytes(s):
        """Decodes raw bytes into a unicode string."""
        if not isinstance(s, bytes):
            return s
        return s.decode("raw_unicode_escape")

    def __call__(self):
        """Reproduce the underlying user event into IDA."""
        raise NotImplementedError("__call__() not implemented")


class MakeCodeEvent(Event):
    __event__ = "make_code"

    def __init__(self, ea):
        super(MakeCodeEvent, self).__init__()
        self.ea = ea

    def __call__(self):
        ida_ua.create_insn(self.ea)


class MakeDataEvent(Event):
    __event__ = "make_data"

    def __init__(self, ea, flags, size, tid):
        super(MakeDataEvent, self).__init__()
        self.ea = ea
        self.flags = flags
        self.size = size
        self.tid = tid

    def __call__(self):
        ida_bytes.create_data(self.ea, self.flags, self.size, self.tid)


class RenamedEvent(Event):
    __event__ = "renamed"

    def __init__(self, ea, new_name, local_name):
        super(RenamedEvent, self).__init__()
        self.ea = ea
        self.new_name = Event.decode(new_name)
        self.local_name = local_name

    def __call__(self):
        flags = ida_name.SN_LOCAL if self.local_name else 0

        try:
            ida_name.set_name(
                self.ea, (self.new_name), flags | ida_name.SN_NOWARN
            )
        except:
            raise Exception(repr((self.ea, (self.new_name), flags | ida_name.SN_NOWARN)))
        ida_kernwin.request_refresh(ida_kernwin.IWID_DISASMS)
        HexRaysEvent.refresh_pseudocode_view(self.ea)


class FuncAddedEvent(Event):
    __event__ = "func_added"

    def __init__(self, start_ea, end_ea):
        super(FuncAddedEvent, self).__init__()
        self.start_ea = start_ea
        self.end_ea = end_ea

    def __call__(self):
        ida_funcs.add_func(self.start_ea, self.end_ea)


class DeletingFuncEvent(Event):
    __event__ = "deleting_func"

    def __init__(self, start_ea):
        super(DeletingFuncEvent, self).__init__()
        self.start_ea = start_ea

    def __call__(self):
        ida_funcs.del_func(self.start_ea)


class SetFuncStartEvent(Event):
    __event__ = "set_func_start"

    def __init__(self, start_ea, new_start):
        super(SetFuncStartEvent, self).__init__()
        self.start_ea = start_ea
        self.new_start = new_start

    def __call__(self):
        ida_funcs.set_func_start(self.start_ea, self.new_start)


class SetFuncEndEvent(Event):
    __event__ = "set_func_end"

    def __init__(self, start_ea, new_end):
        super(SetFuncEndEvent, self).__init__()
        self.start_ea = start_ea
        self.new_end = new_end

    def __call__(self):
        ida_funcs.set_func_end(self.start_ea, self.new_end)


class FuncTailAppendedEvent(Event):
    __event__ = "func_tail_appended"

    def __init__(self, start_ea_func, start_ea_tail, end_ea_tail):
        super(FuncTailAppendedEvent, self).__init__()
        self.start_ea_func = start_ea_func
        self.start_ea_tail = start_ea_tail
        self.end_ea_tail = end_ea_tail

    def __call__(self):
        func = ida_funcs.get_func(self.start_ea_func)
        ida_funcs.append_func_tail(func, self.start_ea_tail, self.end_ea_tail)


class FuncTailDeletedEvent(Event):
    __event__ = "func_tail_deleted"

    def __init__(self, start_ea_func, tail_ea):
        super(FuncTailDeletedEvent, self).__init__()
        self.start_ea_func = start_ea_func
        self.tail_ea = tail_ea

    def __call__(self):
        func = ida_funcs.get_func(self.start_ea_func)
        ida_funcs.remove_func_tail(func, self.tail_ea)


class TailOwnerChangedEvent(Event):
    __event__ = "tail_owner_changed"

    def __init__(self, tail_ea, owner_func):
        super(TailOwnerChangedEvent, self).__init__()
        self.tail_ea = tail_ea
        self.owner_func = owner_func

    def __call__(self):
        tail = ida_funcs.get_fchunk(self.tail_ea)
        ida_funcs.set_tail_owner(tail, self.owner_func)


class CmtChangedEvent(Event):
    __event__ = "cmt_changed"

    def __init__(self, ea, comment, rptble):
        super(CmtChangedEvent, self).__init__()
        self.ea = ea
        self.comment = Event.decode(comment)
        self.rptble = rptble

    def __call__(self):
        ida_bytes.set_cmt(self.ea, (self.comment), self.rptble)


class RangeCmtChangedEvent(Event):
    __event__ = "range_cmt_changed"

    def __init__(self, kind, a, cmt, rptble):
        super(RangeCmtChangedEvent, self).__init__()
        self.kind = kind
        self.start_ea = a.start_ea
        self.end_ea = a.end_ea
        self.cmt = Event.decode(cmt)
        self.rptble = rptble

    def __call__(self):
        cmt = (self.cmt)
        if self.kind == ida_range.RANGE_KIND_FUNC:
            func = ida_funcs.get_func(self.start_ea)
            ida_funcs.set_func_cmt(func, cmt, self.rptble)
        elif self.kind == ida_range.RANGE_KIND_SEGMENT:
            segment = ida_segment.getseg(self.start_ea)
            ida_segment.set_segment_cmt(segment, cmt, self.rptble)
        else:
            raise Exception("Unsupported range kind: %d" % self.kind)


class ExtraCmtChangedEvent(Event):
    __event__ = "extra_cmt_changed"

    def __init__(self, ea, line_idx, cmt):
        super(ExtraCmtChangedEvent, self).__init__()
        self.ea = ea
        self.line_idx = line_idx
        self.cmt = Event.decode(cmt)

    def __call__(self):
        ida_lines.del_extra_cmt(self.ea, self.line_idx)
        isprev = 1 if self.line_idx - 1000 < 1000 else 0
        if not self.cmt:
            return 0
        ida_lines.add_extra_cmt(self.ea, isprev, (self.cmt))


class TiChangedEvent(Event):
    __event__ = "ti_changed"

    def __init__(self, ea, py_type):
        super(TiChangedEvent, self).__init__()
        self.ea = ea
        self.py_type = []
        if py_type:
            self.py_type.extend(Event.decode_bytes(t) for t in py_type)

    def __call__(self):
        py_type = [Event.encode_bytes(t) for t in self.py_type]
        if len(py_type) == 3:
            py_type = py_type[1:]
        if len(py_type) >= 2:
            try:
                ida_typeinf.apply_type(
                    None,
                    py_type[0],  # DefaultEvent(type=event, event_type=ti_changed, ea=4278195233, py_type=['\x1b\x052', ''])
                    py_type[1],
                    self.ea,
                    ida_typeinf.TINFO_DEFINITE,
                )
            except:
                raise Exception(repr(py_type))


class LocalTypesChangedEvent(Event):
    __event__ = "local_types_changed"

    def __init__(self, local_types):
        super(LocalTypesChangedEvent, self).__init__()
        self.local_types = []
        for py_ord, name, type, fields, cmt, fieldcmts, sclass in local_types:
            name = Event.decode_bytes(name)
            type = Event.decode_bytes(type)
            fields = Event.decode_bytes(fields)
            cmt = Event.decode_bytes(cmt)
            fieldcmts = Event.decode_bytes(fieldcmts)
            self.local_types.append(
                (py_ord, name, type, fields, cmt, fieldcmts, sclass)
            )

    def __call__(self):
        from .core import Core

        dll = Core.get_ida_dll()

        get_idati = dll.get_idati
        get_idati.argtypes = []
        get_idati.restype = ctypes.c_void_p

        set_numbered_type = dll.set_numbered_type
        set_numbered_type.argtypes = [
            ctypes.c_void_p,
            ctypes.c_uint32,
            ctypes.c_int,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_char_p,
            ctypes.c_int,
        ]
        set_numbered_type.restype = ctypes.c_int

        py_ti = ida_typeinf.get_idati()
        ordinal_qty = ida_typeinf.get_ordinal_qty(py_ti) - 1
        last_ordinal = self.local_types[-1][0]
        if ordinal_qty < last_ordinal:
            ida_typeinf.alloc_type_ordinals(py_ti, last_ordinal - ordinal_qty)
        else:
            for py_ordinal in range(last_ordinal + 1, ordinal_qty + 1):
                ida_typeinf.del_numbered_type(py_ti, py_ordinal)

        local_types = self.local_types
        for py_ord, name, type, fields, cmt, fieldcmts, sclass in local_types:
            if type:
                ti = get_idati()
                ordinal = ctypes.c_uint32(py_ord)
                ntf_flags = ctypes.c_int(ida_typeinf.NTF_REPLACE)
                name = ctypes.c_char_p(Event.encode_bytes(name))
                type = ctypes.c_char_p(Event.encode_bytes(type))
                fields = ctypes.c_char_p(Event.encode_bytes(fields))
                cmt = ctypes.c_char_p(Event.encode_bytes(cmt))
                fieldcmts = ctypes.c_char_p(Event.encode_bytes(fieldcmts))
                sclass = ctypes.c_int(sclass)
                set_numbered_type(
                    ti,
                    ordinal,
                    ntf_flags,
                    name,
                    type,
                    fields,
                    cmt,
                    fieldcmts,
                    sclass,
                )

        ida_kernwin.request_refresh(ida_kernwin.IWID_LOCTYPS)


class OpTypeChangedEvent(Event):
    __event__ = "op_type_changed"

    def __init__(self, ea, n, op, extra):
        super(OpTypeChangedEvent, self).__init__()
        self.ea = ea
        self.n = n
        self.op = op
        self.extra = extra

    def __call__(self):
        if self.op == "hex":
            ida_bytes.op_hex(self.ea, self.n)
        if self.op == "bin":
            ida_bytes.op_bin(self.ea, self.n)
        if self.op == "dec":
            ida_bytes.op_dec(self.ea, self.n)
        if self.op == "chr":
            ida_bytes.op_chr(self.ea, self.n)
        if self.op == "oct":
            ida_bytes.op_oct(self.ea, self.n)
        if self.op == "offset":
            op_plain_offset(self.ea, self.n, 0)
        if self.op == "enum":
            id = ida_enum.get_enum((self.extra["ename"]))
            ida_bytes.op_enum(self.ea, self.n, id, self.extra["serial"])
        if self.op == "struct":
            path_len = len(self.extra["spath"])
            path = ida_pro.tid_array(path_len)
            for i in range(path_len):
                sname = self.extra["spath"][i]
                path[i] = ida_struct.get_struc_id(sname)
            insn = ida_ua.insn_t()
            ida_ua.decode_insn(insn, self.ea)
            ida_bytes.op_stroff(
                insn, self.n, path.cast(), path_len, self.extra["delta"]
            )
        if self.op == "stkvar":
            ida_bytes.op_stkvar(self.ea, self.n)
        # FIXME: No hooks are called when inverting sign
        # if self.op == 'invert_sign':
        #     idc.toggle_sign(ea, n)


class EnumCreatedEvent(Event):
    __event__ = "enum_created"

    def __init__(self, enum, name):
        super(EnumCreatedEvent, self).__init__()
        self.enum = enum
        self.name = Event.decode(name)

    def __call__(self):
        ida_enum.add_enum(self.enum, (self.name), 0)


class EnumDeletedEvent(Event):
    __event__ = "enum_deleted"

    def __init__(self, ename):
        super(EnumDeletedEvent, self).__init__()
        self.ename = Event.decode(ename)

    def __call__(self):
        ida_enum.del_enum(ida_enum.get_enum((self.ename)))


class EnumRenamedEvent(Event):
    __event__ = "enum_renamed"

    def __init__(self, oldname, newname, is_enum):
        super(EnumRenamedEvent, self).__init__()
        self.oldname = Event.decode(oldname)
        self.newname = Event.decode(newname)
        self.is_enum = is_enum

    def __call__(self):
        if self.is_enum:
            enum = ida_enum.get_enum((self.oldname))
            ida_enum.set_enum_name(enum, (self.newname))
        else:
            emem = ida_enum.get_enum_member_by_name((self.oldname))
            ida_enum.set_enum_member_name(emem, (self.newname))


class EnumBfChangedEvent(Event):
    __event__ = "enum_bf_changed"

    def __init__(self, ename, bf_flag):
        super(EnumBfChangedEvent, self).__init__()
        self.ename = Event.decode(ename)
        self.bf_flag = bf_flag

    def __call__(self):
        enum = ida_enum.get_enum((self.ename))
        ida_enum.set_enum_bf(enum, self.bf_flag)


class EnumCmtChangedEvent(Event):
    __event__ = "enum_cmt_changed"

    def __init__(self, emname, cmt, repeatable_cmt):
        super(EnumCmtChangedEvent, self).__init__()
        self.emname = Event.decode(emname)
        self.cmt = Event.decode(cmt)
        self.repeatable_cmt = repeatable_cmt

    def __call__(self):
        emem = ida_enum.get_enum_member_by_name((self.emname))
        cmt = (self.cmt if self.cmt else "")
        ida_enum.set_enum_cmt(emem, cmt, self.repeatable_cmt)


class EnumMemberCreatedEvent(Event):
    __event__ = "enum_member_created"

    def __init__(self, ename, name, value, bmask):
        super(EnumMemberCreatedEvent, self).__init__()
        self.ename = Event.decode(ename)
        self.name = name
        self.value = value
        self.bmask = bmask

    def __call__(self):
        enum = ida_enum.get_enum((self.ename))
        ida_enum.add_enum_member(
            enum, (self.name), self.value, self.bmask
        )


class EnumMemberDeletedEvent(Event):
    __event__ = "enum_member_deleted"

    def __init__(self, ename, value, serial, bmask):
        super(EnumMemberDeletedEvent, self).__init__()
        self.ename = Event.decode(ename)
        self.value = value
        self.serial = serial
        self.bmask = bmask

    def __call__(self):
        enum = ida_enum.get_enum((self.ename))
        ida_enum.del_enum_member(enum, self.value, self.serial, self.bmask)


class StrucCreatedEvent(Event):
    __event__ = "struc_created"

    def __init__(self, struc, name, is_union):
        super(StrucCreatedEvent, self).__init__()
        self.struc = struc
        self.name = Event.decode(name)
        self.is_union = is_union

    def __call__(self):
        ida_struct.add_struc(
            self.struc, self.name, self.is_union
        )


class StrucDeletedEvent(Event):
    __event__ = "struc_deleted"

    def __init__(self, sname):
        super(StrucDeletedEvent, self).__init__()
        self.sname = Event.decode(sname)

    def __call__(self):
        struc = ida_struct.get_struc_id(self.sname)
        ida_struct.del_struc(ida_struct.get_struc(struc))


class StrucRenamedEvent(Event):
    __event__ = "struc_renamed"

    def __init__(self, oldname, newname):
        super(StrucRenamedEvent, self).__init__()
        self.oldname = Event.decode(oldname)
        self.newname = Event.decode(newname)

    def __call__(self):
        struc = ida_struct.get_struc_id(self.oldname)
        ida_struct.set_struc_name(struc, self.newname)


class StrucCmtChangedEvent(Event):
    __event__ = "struc_cmt_changed"

    def __init__(self, sname, smname, cmt, repeatable_cmt):
        super(StrucCmtChangedEvent, self).__init__()
        self.sname = Event.decode(sname)
        self.smname = Event.decode(smname)
        self.cmt = Event.decode(cmt)
        self.repeatable_cmt = repeatable_cmt

    def __call__(self):
        struc = ida_struct.get_struc_id(self.sname)
        sptr = ida_struct.get_struc(struc)
        cmt = (self.cmt if self.cmt else "")
        if self.smname:
            mptr = ida_struct.get_member_by_name(
                sptr, self.smname
            )
            ida_struct.set_member_cmt(mptr, cmt, self.repeatable_cmt)
        else:
            ida_struct.set_struc_cmt(sptr.id, cmt, self.repeatable_cmt)


class StrucMemberCreatedEvent(Event):
    __event__ = "struc_member_created"

    def __init__(self, sname, fieldname, offset, flag, nbytes, extra):
        super(StrucMemberCreatedEvent, self).__init__()
        self.sname = Event.decode(sname)
        self.fieldname = Event.decode(fieldname)
        self.offset = offset
        self.flag = flag
        self.nbytes = nbytes
        self.extra = extra

    def __call__(self):
        mt = ida_nalt.opinfo_t()
        if ida_bytes.is_struct(self.flag):
            mt.tid = self.extra["id"]
        if ida_bytes.is_off0(self.flag) or ida_bytes.is_off1(self.flag):
            mt.ri = ida_nalt.refinfo_t()
        if ida_bytes.is_strlit(self.flag):
            mt.strtype = self.extra["strtype"]
        struc = ida_struct.get_struc_id(self.sname)
        sptr = ida_struct.get_struc(struc)
        ida_struct.add_struc_member(
            sptr,
            self.fieldname,
            self.offset,
            self.flag,
            mt,
            self.nbytes,
        )


class StrucMemberChangedEvent(Event):
    __event__ = "struc_member_changed"

    def __init__(self, sname, soff, eoff, flag, extra):
        super(StrucMemberChangedEvent, self).__init__()
        self.sname = Event.decode(sname)
        self.soff = soff
        self.eoff = eoff
        self.flag = flag
        self.extra = extra

    def __call__(self):
        mt = ida_nalt.opinfo_t()
        if ida_bytes.is_struct(self.flag):
            mt.tid = self.extra["id"]
        if ida_bytes.is_off0(self.flag) or ida_bytes.is_off1(self.flag):
            mt.ri = ida_nalt.refinfo_t()
        if ida_bytes.is_strlit(self.flag):
            mt.strtype = self.extra["strtype"]
        struc = ida_struct.get_struc_id(self.sname)
        sptr = ida_struct.get_struc(struc)
        ida_struct.set_member_type(
            sptr, self.soff, self.flag, mt, self.eoff - self.soff
        )


class StrucMemberDeletedEvent(Event):
    __event__ = "struc_member_deleted"

    def __init__(self, sname, offset):
        super(StrucMemberDeletedEvent, self).__init__()
        self.sname = Event.decode(sname)
        self.offset = offset

    def __call__(self):
        struc = ida_struct.get_struc_id(self.sname)
        sptr = ida_struct.get_struc(struc)
        ida_struct.del_struc_member(sptr, self.offset)


class StrucMemberRenamedEvent(Event):
    __event__ = "struc_member_renamed"

    def __init__(self, sname, offset, newname):
        super(StrucMemberRenamedEvent, self).__init__()
        self.sname = Event.decode(sname)
        self.offset = offset
        self.newname = Event.decode(newname)

    def __call__(self):
        struc = ida_struct.get_struc_id(self.sname)
        sptr = ida_struct.get_struc(struc)
        ida_struct.set_member_name(
            sptr, self.offset, self.newname
        )


class ExpandingStrucEvent(Event):
    __event__ = "expanding_struc"

    def __init__(self, sname, offset, delta):
        super(ExpandingStrucEvent, self).__init__()
        self.sname = Event.decode(sname)
        self.offset = offset
        self.delta = delta

    def __call__(self):
        struc = ida_struct.get_struc_id(self.sname)
        sptr = ida_struct.get_struc(struc)
        ida_struct.expand_struc(sptr, self.offset, self.delta)


class SegmAddedEvent(Event):
    __event__ = "segm_added_event"

    def __init__(
        self,
        name,
        class_,
        start_ea,
        end_ea,
        orgbase,
        align,
        comb,
        perm,
        bitness,
        flags,
    ):
        super(SegmAddedEvent, self).__init__()
        self.name = Event.decode(name)
        self.class_ = Event.decode(class_)
        self.start_ea = start_ea
        self.end_ea = end_ea
        self.orgbase = orgbase
        self.align = align
        self.comb = comb
        self.perm = perm
        self.bitness = bitness
        self.flags = flags

    def __call__(self):
        seg = ida_segment.segment_t()
        seg.start_ea = self.start_ea
        seg.end_ea = self.end_ea
        seg.orgbase = self.orgbase
        seg.align = self.align
        seg.comb = self.comb
        seg.perm = self.perm
        seg.bitness = self.bitness
        seg.flags = self.flags
        ida_segment.add_segm_ex(
            seg,
            (self.name),
            (self.class_),
            ida_segment.ADDSEG_QUIET | ida_segment.ADDSEG_NOSREG,
        )


class SegmDeletedEvent(Event):
    __event__ = "segm_deleted_event"

    def __init__(self, ea):
        super(SegmDeletedEvent, self).__init__()
        self.ea = ea

    def __call__(self):
        ida_segment.del_segm(
            self.ea, ida_segment.SEGMOD_KEEP | ida_segment.SEGMOD_SILENT
        )


class SegmStartChangedEvent(Event):
    __event__ = "segm_start_changed_event"

    def __init__(self, newstart, ea):
        super(SegmStartChangedEvent, self).__init__()
        self.newstart = newstart
        self.ea = ea

    def __call__(self):
        ida_segment.set_segm_start(self.ea, self.newstart, 0)


class SegmEndChangedEvent(Event):
    __event__ = "segm_end_changed_event"

    def __init__(self, newend, ea):
        super(SegmEndChangedEvent, self).__init__()
        self.newend = newend
        self.ea = ea

    def __call__(self):
        ida_segment.set_segm_end(self.ea, self.newend, 0)


class SegmNameChangedEvent(Event):
    __event__ = "segm_name_changed_event"

    def __init__(self, ea, name):
        super(SegmNameChangedEvent, self).__init__()
        self.ea = ea
        self.name = Event.decode(name)

    def __call__(self):
        seg = ida_segment.getseg(self.ea)
        ida_segment.set_segm_name(seg, (self.name))


class SegmClassChangedEvent(Event):
    __event__ = "segm_class_changed_event"

    def __init__(self, ea, sclass):
        super(SegmClassChangedEvent, self).__init__()
        self.ea = ea
        self.sclass = Event.decode(sclass)

    def __call__(self):
        seg = ida_segment.getseg(self.ea)
        ida_segment.set_segm_class(seg, (self.sclass))


class SegmAttrsUpdatedEvent(Event):
    __event__ = "segm_attrs_updated_event"

    def __init__(self, ea, perm, bitness):
        super(SegmAttrsUpdatedEvent, self).__init__()
        self.ea = ea
        self.perm = perm
        self.bitness = bitness

    def __call__(self):
        s = ida_segment.getseg(self.ea)
        s.perm = self.perm
        s.bitness = self.bitness
        s.update()


class SegmMoved(Event):
    __event__ = "segm_moved_event"

    def __init__(self, from_ea, to_ea, changed_netmap):
        super(SegmMoved, self).__init__()
        self.from_ea = from_ea
        self.to_ea = to_ea
        self.changed_netmap = changed_netmap

    def __call__(self):
        flags = ida_segment.MFS_NETMAP if self.changed_netmap else 0
        s = ida_segment.getseg(self.from_ea)
        ida_segment.move_segm(s, self.to_ea, flags)


class UndefinedEvent(Event):
    __event__ = "undefined"

    def __init__(self, ea):
        super(UndefinedEvent, self).__init__()
        self.ea = ea

    def __call__(self):
        ida_bytes.del_items(self.ea)


class BytePatchedEvent(Event):
    __event__ = "byte_patched"

    def __init__(self, ea, value):
        super(BytePatchedEvent, self).__init__()
        self.ea = ea
        self.value = value

    def __call__(self):
        ida_bytes.patch_byte(self.ea, self.value)


class SgrChanged(Event):
    __event__ = "sgr_changed"

    @staticmethod
    def get_sreg_ranges(rg):
        sreg_ranges = []
        sreg_ranges_qty = ida_segregs.get_sreg_ranges_qty(rg)
        for n in range(sreg_ranges_qty):
            sreg_range = ida_segregs.sreg_range_t()
            ida_segregs.getn_sreg_range(sreg_range, rg, n)
            sreg_ranges.append(
                (
                    sreg_range.start_ea,
                    sreg_range.end_ea,
                    sreg_range.val,
                    sreg_range.tag,
                )
            )
        return sreg_ranges

    def __init__(self, rg, sreg_ranges):
        super(SgrChanged, self).__init__()
        self.rg = rg
        self.sreg_ranges = sreg_ranges

    def __call__(self):
        new_ranges = {r[0]: r for r in self.sreg_ranges}
        old_ranges = {r[0]: r for r in SgrChanged.get_sreg_ranges(self.rg)}

        start_eas = sorted(
            set(list(new_ranges.keys()) + list(old_ranges.keys()))
        )
        for start_ea in start_eas:
            new_range = new_ranges.get(start_ea, None)
            old_range = old_ranges.get(start_ea, None)

            if new_range and not old_range:
                _, __, val, tag = new_range
                ida_segregs.split_sreg_range(start_ea, self.rg, val, tag, True)

            if not new_range and old_range:
                ida_segregs.del_sreg_range(start_ea, self.rg)

            if new_range and old_range:
                _, __, new_val, new_tag = new_range
                _, __, old_val, old_tag = old_range
                if new_val != old_val or new_tag != old_tag:
                    ida_segregs.split_sreg_range(
                        start_ea, self.rg, new_val, new_tag, True
                    )

        ida_kernwin.request_refresh(ida_kernwin.IWID_SEGREGS)


# class GenRegvarDefEvent(Event):
#    __event__ = "gen_regvar_def"
#
#    def __init__(self, ea, canonical_name, new_name, cmt):
#        super(GenRegvarDefEvent, self).__init__()
#        self.ea = ea
#        self.canonical_name = Event.decode(canonical_name)
#        self.new_name = Event.decode(new_name)
#        self.cmt = Event.decode(cmt)
#
#    def __call__(self):
#        func = ida_funcs.get_func(self.ea)
#        ida_frame.add_regvar(
#            func,
#            func.start_ea,
#            func.end_ea,
#            (self.canonical_name),
#            (self.new_name),
#            (self.cmt),
#        )


class HexRaysEvent(Event):
    @staticmethod
    def refresh_pseudocode_view(ea):
        """Refreshes the pseudocode view in IDA."""
        names = ["Pseudocode-%c" % chr(ord("A") + i) for i in range(5)]
        for name in names:
            widget = ida_kernwin.find_widget(name)
            if widget:
                vu = ida_hexrays.get_widget_vdui(widget)

                # Check if the address is in the same function
                func_ea = vu.cfunc.entry_ea
                func = ida_funcs.get_func(func_ea)
                if ida_funcs.func_contains(func, ea):
                    vu.refresh_view(True)


class UserLabelsEvent(HexRaysEvent):
    __event__ = "user_labels"

    def __init__(self, ea, labels):
        super(UserLabelsEvent, self).__init__()
        self.ea = ea
        self.labels = labels

    def __call__(self):
        labels = ida_hexrays.user_labels_new()
        for org_label, name in self.labels:
            name = (name)
            ida_hexrays.user_labels_insert(labels, org_label, name)
        ida_hexrays.save_user_labels(self.ea, labels)
        HexRaysEvent.refresh_pseudocode_view(self.ea)


class UserCmtsEvent(HexRaysEvent):
    __event__ = "user_cmts"

    def __init__(self, ea, cmts):
        super(UserCmtsEvent, self).__init__()
        self.ea = ea
        self.cmts = cmts

    def __call__(self):
        cmts = ida_hexrays.user_cmts_new()
        for (tl_ea, tl_itp), cmt in self.cmts:
            tl = ida_hexrays.treeloc_t()
            tl.ea = tl_ea
            tl.itp = tl_itp
            cmts.insert(tl, ida_hexrays.citem_cmt_t((cmt)))
        ida_hexrays.save_user_cmts(self.ea, cmts)
        HexRaysEvent.refresh_pseudocode_view(self.ea)


class UserIflagsEvent(HexRaysEvent):
    __event__ = "user_iflags"

    def __init__(self, ea, iflags):
        super(UserIflagsEvent, self).__init__()
        self.ea = ea
        self.iflags = iflags

    def __call__(self):
        # FIXME: Hey-Rays bindings are currently broken
        # iflags = ida_hexrays.user_iflags_new()
        # for (cl_ea, cl_op), f in self.iflags:
        #     cl = ida_hexrays.citem_locator_t(cl_ea, cl_op)
        #     iflags.insert(cl, f)
        # ida_hexrays.save_user_iflags(self.ea, iflags)

        ida_hexrays.save_user_iflags(self.ea, ida_hexrays.user_iflags_new())
        HexRaysEvent.refresh_pseudocode_view(self.ea)

        cfunc = ida_hexrays.decompile(self.ea)
        for (cl_ea, cl_op), f in self.iflags:
            cl = ida_hexrays.citem_locator_t(cl_ea, cl_op)
            cfunc.set_user_iflags(cl, f)
        cfunc.save_user_iflags()
        HexRaysEvent.refresh_pseudocode_view(self.ea)


class UserLvarSettingsEvent(HexRaysEvent):
    __event__ = "user_lvar_settings"

    def __init__(self, ea, lvar_settings):
        super(UserLvarSettingsEvent, self).__init__()
        self.ea = ea
        self.lvar_settings = lvar_settings

    def __call__(self):
        lvinf = ida_hexrays.lvar_uservec_t()
        lvinf.lvvec = ida_hexrays.lvar_saved_infos_t()
        for lv in self.lvar_settings["lvvec"]:
            lvinf.lvvec.push_back(
                UserLvarSettingsEvent._get_lvar_saved_info(lv)
            )
        lvinf.sizes = ida_pro.intvec_t()
        if "sizes" in self.lvar_settings:
            for i in self.lvar_settings["sizes"]:
                lvinf.sizes.push_back(i)
        lvinf.lmaps = ida_hexrays.lvar_mapping_t()
        for key, val in self.lvar_settings["lmaps"]:
            key = UserLvarSettingsEvent._get_lvar_locator(key)
            val = UserLvarSettingsEvent._get_lvar_locator(val)
            ida_hexrays.lvar_mapping_insert(lvinf.lmaps, key, val)
        lvinf.stkoff_delta = self.lvar_settings["stkoff_delta"]
        lvinf.ulv_flags = self.lvar_settings["ulv_flags"]
        ida_hexrays.save_user_lvar_settings(self.ea, lvinf)
        HexRaysEvent.refresh_pseudocode_view(self.ea)

    @staticmethod
    def _get_lvar_saved_info(dct):
        lv = ida_hexrays.lvar_saved_info_t()
        lv.ll = UserLvarSettingsEvent._get_lvar_locator(dct["ll"])
        lv.name = (dct["name"])
        lv.type = UserLvarSettingsEvent._get_tinfo(dct["type"])
        lv.cmt = (dct["cmt"])
        lv.flags = dct["flags"]
        return lv

    @staticmethod
    def _get_tinfo(dct):
        type, fields, fldcmts = dct
        type = Event.encode_bytes(type)
        fields = Event.encode_bytes(fields)
        fldcmts = Event.encode_bytes(fldcmts)

        type_ = ida_typeinf.tinfo_t()
        if type is not None:
            type_.deserialize(None, type, fields, fldcmts)
        return type_

    @staticmethod
    def _get_lvar_locator(dct):
        ll = ida_hexrays.lvar_locator_t()
        ll.location = UserLvarSettingsEvent._get_vdloc(dct["location"])
        ll.defea = dct["defea"]
        return ll

    @staticmethod
    def _get_vdloc(dct):
        location = ida_hexrays.vdloc_t()
        if dct["atype"] == ida_typeinf.ALOC_NONE:
            pass
        elif dct["atype"] == ida_typeinf.ALOC_STACK:
            location.set_stkoff(dct["stkoff"])
        elif dct["atype"] == ida_typeinf.ALOC_DIST:
            pass  # FIXME: Not supported
        elif dct["atype"] == ida_typeinf.ALOC_REG1:
            location.set_reg1(dct["reg1"])
        elif dct["atype"] == ida_typeinf.ALOC_REG2:
            location.set_reg2(dct["reg1"], dct["reg2"])
        elif dct["atype"] == ida_typeinf.ALOC_RREL:
            pass  # FIXME: Not supported
        elif dct["atype"] == ida_typeinf.ALOC_STATIC:
            location.set_ea(dct["ea"])
        elif dct["atype"] == ida_typeinf.ALOC_CUSTOM:
            pass  # FIXME: Not supported
        return location


class UserNumformsEvent(HexRaysEvent):
    __event__ = "user_numforms"

    def __init__(self, ea, numforms):
        super(UserNumformsEvent, self).__init__()
        self.ea = ea
        self.numforms = numforms

    def __call__(self):
        numforms = ida_hexrays.user_numforms_new()
        for _ol, _nf in self.numforms:
            ol = ida_hexrays.operand_locator_t(_ol["ea"], _ol["opnum"])
            nf = ida_hexrays.number_format_t()
            nf.flags = _nf["flags"]
            nf.opnum = (_nf["opnum"])
            nf.props = (_nf["props"])
            nf.serial = _nf["serial"]
            nf.org_nbytes = (_nf["org_nbytes"])
            nf.type_name = (_nf["type_name"])
            ida_hexrays.user_numforms_insert(numforms, ol, nf)
        ida_hexrays.save_user_numforms(self.ea, numforms)
        HexRaysEvent.refresh_pseudocode_view(self.ea)
