
ENTRY(__loader_start)

SECTIONS
{
  .text 0x215c : {*(.text .stub .text.* .gnu.linkonce.t.*)}
}
    