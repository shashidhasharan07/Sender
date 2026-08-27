1: {
    "type": "dynamic_array",
    "name": "PTData",
    "max_count": 5,

    "element": {
        "type": "struct",
        "fmt": "!IIIIIIII",
        "name": "PT",

        "fields": [

            # -----------------------------
            # TARGET STATUS
            # -----------------------------

            ("target_status", {
                "bitfield": [

                    (
                        "target_type",
                        3,
                        {
                            "enum": {
                                0: "UNKNOWN",
                                1: "AIR",
                                2: "GROUND",
                                3: "SEA"
                            }
                        }
                    ),

                    (
                        "track_status",
                        2,
                        {
                            "enum": {
                                0: "FREE",
                                1: "SEARCH",
                                2: "TRACK",
                                3: "LOCKED"
                            }
                        }
                    ),

                    (
                        "target_quality",
                        3,
                        None
                    )
                ]
            }),

            # -----------------------------
            # OTHER PARAMETERS
            # -----------------------------

            ("track_no", None),

            ("sensor_id", None),

            ("timetag_msb", None),

            ("timetag_lsb", None),

            ("tgt_lat", None),

            ("tgt_lon", None),

            ("tgt_h_above_sea", None)
        ]
    }
},



try:

    decoded, labels = decode_from_icd(
        opcode,
        payload
    )

except Exception as e:

    print("❌ ICD DECODE ERROR")
    print("Opcode:", opcode)
    print("Error:", e)

    continue

print("Decoded parameter count:", len(decoded))

for name, value in decoded.items():
    print(f"{name} = {value}")

store.add(
    opcode,
    decoded,
    msg_tod,
    msg_serial_num
)

print(
    "Stored parameters:",
    store.params(opcode)
)

logger_rx.log(
    msg_serial_num,
    opcode,
    decoded,
    labels,
    msg_tod
)



















