
package MessageDigest;

/**
 *
 * @author Marc Greim
 */
public class BLAKE512 extends java.security.MessageDigest {
    
    public BLAKE512(){
        super("BLAKE-512");
    }
    
    private static final int ROUNDS = 16;
    
    private static final long intmask = (((long)Integer.MAX_VALUE)<<1)|1;
    
    private static final int perm[][] = 
    {
        {0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14, 15},
        {14, 10,  4,  8,  9, 15, 13,  6,  1, 12,  0,  2, 11,  7,  5,  3},
        {11,  8 ,12 , 0  ,5 , 2 ,15 ,13, 10 ,14 , 3 , 6 , 7 , 1 , 9 , 4},
        {7,  9 , 3 , 1 ,13 ,12 ,11 ,14 , 2 , 6 , 5 ,10 , 4 , 0 ,15 , 8},
        {9 , 0 , 5 , 7 , 2 , 4 ,10, 15 ,14 , 1 ,11 ,12 , 6 , 8 , 3 ,13},
        {2, 12 , 6 ,10 , 0 ,11 , 8 , 3 , 4, 13 , 7 , 5 ,15, 14,  1 , 9},
        {12,  5 , 1, 15, 14, 13 , 4 ,10 , 0 , 7 , 6 , 3 , 9 , 2 , 8 ,11},
        {13, 11 , 7 ,14, 12,  1 , 3 , 9 , 5 , 0, 15,  4 , 8 , 6 , 2 ,10},
        {6 ,15 ,14  ,9, 11 , 3 , 0 , 8, 12 , 2 ,13 , 7 , 1 , 4, 10 , 5},
        {10 , 2 , 8 , 4 , 7 , 6 , 1 , 5 ,15, 11 , 9 ,14  ,3, 12, 13 , 0}      
    };
    
    private static final long initialvalue[] = {
        (((long)0x6A09E667)<<32)| (((long)0xF3BCC908)&intmask),
        (((long)0xBB67AE85)<<32)| (((long)0x84CAA73B)&intmask),
        (((long)0x3C6EF372)<<32)| (((long)0xFE94F82B)&intmask),
        (((long)0xA54FF53A)<<32)| (((long)0x5F1D36F1)&intmask),
        (((long)0x510E527F)<<32)| (((long)0xADE682D1)&intmask),
        (((long)0x9B05688C)<<32)| (((long)0x2B3E6C1F)&intmask),
        (((long)0x1F83D9AB)<<32)| (((long)0xFB41BD6B)&intmask),
        (((long)0x5BE0CD19)<<32)| (((long)0x137E2179)&intmask)
    };
    
    private static final long constant[] = {
        (((long)0x243F6A88)<<32)|(((long)0x85A308D3)&intmask),
        (((long)0x13198A2E)<<32)|(((long)0x03707344)&intmask),
        (((long)0xA4093822)<<32)|(((long)0x299F31D0)&intmask),
        (((long)0x082EFA98)<<32)|(((long)0xEC4E6C89)&intmask),
        
        (((long)0x452821E6)<<32)|(((long)0x38D01377)&intmask),
        (((long)0xBE5466CF)<<32)|(((long)0x34E90C6C)&intmask),
        (((long)0xC0AC29B7)<<32)|(((long)0xC97C50DD)&intmask),
        (((long)0x3F84D5B5)<<32)|(((long)0xB5470917)&intmask),
        
        (((long)0x9216D5D9)<<32)|(((long)0x8979FB1B)&intmask),
        (((long)0xD1310BA6)<<32)|(((long)0x98DFB5AC)&intmask),
        (((long)0x2FFD72DB)<<32)|(((long)0xD01ADFB7)&intmask),
        (((long)0xB8E1AFED)<<32)|(((long)0x6A267E96)&intmask),
        
        (((long)0xBA7C9045)<<32)|(((long)0xF12C7F99)&intmask),
        (((long)0x24A19947)<<32)|(((long)0xB3916CF7)&intmask),
        (((long)0x0801F2E2)<<32)|(((long)0x858EFC16)&intmask),
        (((long)0x636920D8)<<32)|(((long)0x71574E69)&intmask)
    };
    
    private static final long nullsalt[] = 
    {
        0,
        0,
        0,
        0
    };

    // corresponding a,...,d index for a given i
    public static final int[][] Gindex = {
        {0,4,8,12},
        {1,5,9,13},
        {2,6,10,14},
        {3,7,11,15},
        {0,5,10,15},
        {1,6,11,12},
        {2,7,8,13},
        {3,4,9,14}
    };
    
    //byte to long conversion
    static long getLong(byte[] b, int off) {
        return  ((b[off + 7] & 0xFFL)      ) +
                ((b[off + 6] & 0xFFL) <<  8) +
                ((b[off + 5] & 0xFFL) << 16) +
                ((b[off + 4] & 0xFFL) << 24) +
                ((b[off + 3] & 0xFFL) << 32) +
                ((b[off + 2] & 0xFFL) << 40) +
                ((b[off + 1] & 0xFFL) << 48) +
                (((long) b[off])      << 56);
    }
    //long to byte conversion
    static void putLong(byte[] b, int off, long val) {
        b[off + 7] = (byte) (val       );
        b[off + 6] = (byte) (val >>>  8);
        b[off + 5] = (byte) (val >>> 16);
        b[off + 4] = (byte) (val >>> 24);
        b[off + 3] = (byte) (val >>> 32);
        b[off + 2] = (byte) (val >>> 40);
        b[off + 1] = (byte) (val >>> 48);
        b[off    ] = (byte) (val >>> 56);
    }

    
    // internal buffer for one block of data (1024 bit)
    private final byte[] buffer = new byte[128];
    private int bufferpos = 0;
    
    // internal buffer for one converted block of data(16 * long)
    private final long[] m = new long[16];
    
    // internal buffer for hash state (16 * long)
    private final long[] v = new long[16];
    
    /** internal buffer for total bit-length of the message
     * IMPORTANT NOTICE:    DUE TO THE HIGH UNLIKELINESS OF A MESSAGE THAT EXCEEDS 2^63 bits ( = 1.153 exabytes)
     *                      ONLY THE LAST 63 BITs OF THE SPECIFIED 128 BITs ARE IN USE 
    */
    private final long[] l = {0,0};
    
    // internal buffer for salt (4 * long)
    private final long[] s = new long[4];
    
    // buffer for hash
    private final long[] h = java.util.Arrays.copyOf(initialvalue, 8);
    
    
    
    private void G(int i,int r,long[] v,long[] m){
        int a = Gindex[i][0];
        int b = Gindex[i][1];
        int c = Gindex[i][2];
        int d = Gindex[i][3];
        
        v[a] = v[a] + v[b] + ( m[perm[r%10][2*i]] ^ constant[perm[r%10][(2*i)+1]]);
        
        v[d] = java.lang.Long.rotateRight((v[d] ^ v[a]),32);
        
        v[c] = v[c] + v[d];
        
        v[b] = java.lang.Long.rotateRight((v[b] ^ v[c]),25);
        
        v[a] = v[a] + v[b] + ( m[perm[r%10][(2*i)+1]] ^ constant[perm[r%10][2*i]]);
        
        v[d] = java.lang.Long.rotateRight((v[d] ^ v[a]),16);
        
        v[c] = v[c] + v[d];
        
        v[b] = java.lang.Long.rotateRight((v[b] ^ v[c]),11);
        
    }
    private void Round(int r,long[] v,long[] m){
        for (int i = 0;i<8;i++){
            G(i,r,v,m);
        }
    }
    private void Finalize (long[] v,long[] h,long[] s){
        for (int i = 0;i<8;i++){
            h[i] = h[i] ^ s[i%4] ^ v[i] ^ v[i+8];
        }
    }
    private void Initialize (long[] v,long[] h,long[] s,long t0,long t1){
        
        java.lang.System.arraycopy(h, 0, v, 0, 8);
        
        v[8]    =   s[0] ^ constant[0];
        v[9]    =   s[1] ^ constant[1];
        v[10]   =   s[2] ^ constant[2];
        v[11]   =   s[3] ^ constant[3];
        
        v[12]   =   t0 ^ constant[4];
        v[13]   =   t0 ^ constant[5];
        v[14]   =   t1 ^ constant[6];
        v[15]   =   t1 ^ constant[7];
        
    }
    private void Calculate(long[] v,long[] h,long[] m,long[] s,long[] l){
        Initialize(v,h,s,l[0],l[1]); 
        for (int i = 0 ; i<ROUNDS;i++){
            Round(i,v,m);
        }
        Finalize(v,h,s);
    }
    private void hashBlock(){
        //convert byte[] to long[] for performance
        for (int i = 0; i<16;i++){
            m[i] = getLong(buffer,(i*8));
        }
        Calculate(v,h,m,s,l);
    }
    private void hashBlock(byte[] buf,int off){
        //convert byte[] to long[] for performance
        for (int i = 0; i<16;i++){
            m[i] = getLong(buf,(i*8)+off);
        }
        Calculate(v,h,m,s,l);
    }
    
    @Override
    protected void engineUpdate(byte input) {
        buffer[bufferpos] = input;
        bufferpos++;
        if (bufferpos == 128){
            l[0] += 1024;
            hashBlock(buffer,0);
            bufferpos = 0;
        }
    }

    @Override
    protected void engineUpdate(byte[] input, int offset, int len) {
        while (len > 128){
            if (bufferpos == 0){
                l[0] += 1024;
                hashBlock(input,offset);
                offset += 128;
                len -= 128;
            } else {
                java.lang.System.arraycopy(input, offset, buffer, bufferpos, 128-bufferpos);
                l[0] += 1024;
                hashBlock();
                offset += 128-bufferpos;
                len -= 128-bufferpos;
                bufferpos = 0;
            }
        }
        if (len > (128-bufferpos)){
            java.lang.System.arraycopy(input, offset, buffer, bufferpos, 128-bufferpos);
            l[0] += 1024;
            hashBlock();
            offset += 128-bufferpos;
            len -= 128-bufferpos;
            bufferpos = 0;
        }
        if (len>0){
            java.lang.System.arraycopy(input, offset, buffer, bufferpos, len);
            bufferpos += len;
        }
    }

    @Override
    protected byte[] engineDigest() {
        byte[] retur = new byte[64];
        if (retur != null){
            if (bufferpos >111){
                // if the datalength exceeds 111 bytes 2 blocks are needed for padding
                //Block 1
                java.util.Arrays.fill(m, 0);                                                                //reset buffer
                
                for (int i = 0;i<bufferpos ;i++){                                                           //slower conversion implementation but compatible with uneven bytecount
                    m[i>>3] = m[i>>3] + ((buffer[i]&0xFFL)<<((7-(i&7))*8));
                }
                m[bufferpos>>3] = m[bufferpos>>3] + ((Byte.MIN_VALUE)&0xFFL)<<((7-(bufferpos&7))*8);        //append bit 1 as specified
                l[0] = l[0]+(bufferpos *8);                                                                 // increase bit counter
                Calculate(v,h,m,s,l);                                                                       //hash
                //Block 2
                java.util.Arrays.fill(m, 0);                                                                //reset buffer
                m[15] = l[0];                                                                               //append bit length
                m[13] = 1;                                                                                  // set bit 1 before the 128 bit length value
                l[0] = 0;                                                                                   // set length to 0 because this block contains no message data
                Calculate(v,h,m,s,l);                                                                       //hash
            } else {
                // if the datalength doesn't exceed 111 byte then the padding can be done within the current block
                java.util.Arrays.fill(m, 0);                                                                //reset buffer
                for (int i = 0;i<bufferpos ;i++){                                                           //slower conversion implementation but compatible with uneven bytecount
                    m[i>>3] = m[i>>3] + ((buffer[i]&0xFFL)<<((7-(i&7))*8));
                }
                m[bufferpos>>3] = m[bufferpos>>3] + ((Byte.MIN_VALUE)&0xFFL)<<((7-(bufferpos&7))*8);        //append bit 1 as specified
                m[13] = m[13] + 1;                                                                          // set bit 1 before the 128 bit length value
                l[0] = l[0] + (bufferpos*8);                                                                // increase bit counter
                m[15] = l[0];                                                                               //append bit length
                Calculate(v,h,m,s,l);                                                                       //hash
            }
//            System.out.println();                                                                           //debug
            for (int i = 0;i<8 ;i++){
                putLong(retur,i*8,h[i]);
//                java.lang.System.out.println(Long.toHexString(h[i]));                                       //debug
            }
        }
        engineReset();                                                                                      // reset engine
        return retur;
    }

    @Override
    protected void engineReset() { 
        java.util.Arrays.fill(l, 0);                                //reset bit-counter
        java.lang.System.arraycopy(initialvalue, 0, h, 0, 8);       //reset hash to initial value
        java.lang.System.arraycopy(nullsalt,0,s,0,4);               //reset salt
        bufferpos = 0;                                              //reset buffer position
    }
    
}
