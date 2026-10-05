unit_vals = {
    "KG_GM" : 1000,
    "GM_KG" : 0.001,
    "LB_KG" : 0.453592,
    "GM_LB" : 0.00220462,
    "LB_GM" : 453.592,
    "KG_LB" : 2.20462,
    "KG_TON" : 0.001,
    "TON_KG" : 1000,
    "LTR_ML" : 1000,
    "ML_LTR" : 0.001,
    "LTR_GAL" : 0.264172,
    "GAL_LTR" : 3.78541,
    "ML_GAL" : 0.000264172,
    "GAL_ML" : 3785.41,
    "PC_NOS" : 1,
    "NOS_PC" :1
}

keys = unit_vals.keys()
allowed = {k.split("_")[0] for k in keys}

to = "GM"
be = "KG"

def unit_convertor(to , be , val):
    key = f"{to}_{be}"
    if key in unit_vals.keys():
        return val * unit_vals[key]
    else:
        return "Conversion not supported"
    
print(unit_convertor(to, be, 4519.25))