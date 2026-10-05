/*
  NullReceiver / DPRK "Contagious Interview" npm loader
  Triage of /home/ubuntu/mal.txt  (sha256 df5e8b54b7ce827acf2e1fbb34300f3c3fc21b2632fb8d97b2db78fd3b3bd314)

  Two rules, because the loader's meaningful strings are NOT plaintext in the file:
  they live XOR'd (single byte 0xa2) inside a rotated hex string-array and are only
  materialised at runtime.  A rule written against "/0x/cls" or the wallet address
  will MISS the shipped artefact.

    rule 1  NullReceiver_Loader_Obfuscated_Artefact  -> matches the file as shipped
    rule 2  NullReceiver_Loader_Decoded_Indicators   -> matches decoded/analyst copies,
                                                        sandbox reports, unpacked variants

  Logic validated by re-implementing both condition sets in Python:
    - rule 1 matches the sample
    - 0 false positives across 17,384 benign .js files (/usr/lib/node_modules,
      /usr/share/nodejs, /usr/lib/nodejs)
    - a benign `spawn('node',['-e',...],{detached:true})` control file is NOT flagged
  (The `yara`/`yarac` binaries are not installed here, so this has not been compiled
   by YARA itself - verify with `yarac nullreceiver_loader.yar /dev/null` on a box
   that has YARA before deploying.)
*/

import "math"

rule NullReceiver_Loader_Obfuscated_Artefact
{
    meta:
        author      = "T (appsec)"
        date        = "2026-10-05"
        description = "NullReceiver blockchain dead-drop stage-1 loader, as shipped (hex string-array + single-byte XOR decoder + detached node -e stager)"
        reference   = "https://github.com/advisories/GHSA-44q9-v3f9-xcx6"
        family      = "NullReceiver"
        confidence  = "high on this artefact; re-obfuscated builds may need the regexes relaxed"
        tlp         = "CLEAR"

    strings:
        // --- the decoder core: hex string-array + rotation + byte-wise XOR ---
        $hexmap  = "['match'](/.{1,2}/g)" ascii          // hex string -> byte array
        $u8      = "new Uint8Array(" ascii
        $rot_a   = "['push'](" ascii
        $rot_b   = "['shift']()" ascii
        $tbl     = /=\['[0-9a-fA-F]{20,}',/ ascii        // decoy string-array table (many entries)

        // --- the stager that survives in plaintext ---
        $spawn_e = "'-e'," ascii                          // spawn(node, ['-e', payload])
        $detach  = "'detached':!![]" ascii
        $ignore  = "'stdio':" ascii

        // --- plaintext markers specific to this build ---
        $sechead = "Sec-V" ascii                          // custom request header (plaintext in call site)
        $tagpre  = "global.i = '" ascii                   // campaign/build tag assignment

    condition:
        filesize < 2MB
        and #tbl >= 5
        and $hexmap and $u8 and $rot_a and $rot_b
        and (
              ($spawn_e and $detach)
              or ($sechead and $ignore)
              or ($tagpre and $spawn_e)
        )
}


rule NullReceiver_Loader_Decoded_Indicators
{
    meta:
        author      = "T (appsec)"
        date        = "2026-10-05"
        description = "NullReceiver loader indicators visible after deobfuscation, in sandbox memory/strings output, or in an unpacked/analyst copy"
        reference   = "https://github.com/advisories/GHSA-44q9-v3f9-xcx6"
        family      = "NullReceiver"
        tlp         = "CLEAR"

    strings:
        $wallet1 = "0xa322e5f3d311d3080e6f0121063e9adc2490ef1a" ascii nocase
        $wallet2 = "0xa322E5f3D311D3080e6f0121063e9aDC2490Ef1a" ascii
        $path_cls= "/0x/cls" ascii
        $path_ls = "/0x/ls" ascii
        $hdrb64  = "x-payload-b64" ascii nocase
        $empty   = "Empty payload body" ascii
        $nohdr   = "Missing X-Payload-B64" ascii
        $rpc1    = "eth_getBlockByNumber" ascii
        $rpc2    = "eth_getTransactionCount" ascii
        $indexer = "eth.blockscout.com/api" ascii
        $envrpc  = "ETH_RPC_URL" ascii
        $prelude = "global['r']=require" ascii
        $prelude2= "global['m']=module" ascii
        $marker  = "helloipbot!!" ascii                       // static tail of the dead-drop tx.to

    condition:
        filesize < 4MB
        and (
              $wallet1 or $wallet2
              or 3 of ($path_cls, $path_ls, $hdrb64, $empty, $nohdr, $rpc1, $rpc2, $indexer, $envrpc, $prelude, $prelude2)
        )
}
