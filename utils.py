#Credit: https://gist.github.com/henrique-marcomini-movile/a973227bf91a3452da0db5e452772b78#file-mix_columns-py
#Tool for MixColumns for matrix multiplication by 2
def multiply_by_2(v):
    s = v << 1 #Shift value up by 1
    s &= 0xff #Ensure it does not go out of bounds
    if (v & 128) != 0: #XOR the value with ox1b if high bit has been one
        s = s ^ 0x1b
    return s

def multiply_by_3(v):
    return multiply_by_2(v) ^ v
