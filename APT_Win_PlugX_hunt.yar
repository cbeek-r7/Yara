rule Win_Mal_PlugX {

author = "Christiaan Beek at rapid7 dot com"
        date = "2023-01-13"
        version = "1"
        description = "rule to detect PlugX dll file"

  strings:
    $0 = {00008A7F0000007F0000037F0000897F00008B7F0000017F0000817F0000887F0000807F0000867F0000837F0000857F0000827F0000847F0000047F0000027F0000}
    $1 = {803C07447515807C07015A750E807C07024A7507807C0703537405473BFA7CE03BFA}
    $2 = {803C01447515807C01015A750E807C01024B7507807C0103537405413BCA7CE03BCA7C}
    $3 = {CCCCCCCCCCCC518D4C24042BC81BC0F7D023C88BC42500F0FFFF3BC8720A8BC159948B00890424C32D001000008500EBE9}
  condition:
    all of them and filesize < 300000
}