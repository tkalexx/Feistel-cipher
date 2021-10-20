using System;
using System.Text;

namespace SetF
{
    class Program
    {
        public static string feistel_crypt(string str, string key)
        {
            if (key.Length < 8)
                throw new ArgumentException("Very small key! (min = 8 symbols)");

            byte[] str_arr = Encoding.Default.GetBytes(str);
            byte[] key_arr = Encoding.Default.GetBytes(key);
            int diff = str_arr.Length % 8;
            if (diff != 0)
            {
                byte[] temp = new byte[str_arr.Length + (8 - diff)];
                Array.Copy(str_arr, temp, str_arr.Length);
                str_arr = temp;
            }

            byte[] res_arr = new byte[str_arr.Length];
            for (int i = 0; i < str_arr.Length; i = i + 8)
            {
                byte[] block = new byte[8];
                Array.Copy(str_arr, i, block, 0, 8);

                for (int j = 0; j <= 9; j++)
                {
                    byte[] subblock_left_arr = new byte[4];
                    Array.Copy(block, subblock_left_arr, 4);
                    byte[] subblock_right_arr = new byte[4];
                    Array.Copy(block, 4, subblock_right_arr, 0, 4);


                    byte[] subblock_key_arr = new byte[4];
                    Array.Copy(key_arr, subblock_key_arr, 4);
                    subblock_key_arr = shift_key_left(key_arr, j);

                    if (j != 9)
                        block = crypt_block(subblock_left_arr, subblock_right_arr, subblock_key_arr, false);
                    else
                        block = crypt_block(subblock_left_arr, subblock_right_arr, subblock_key_arr, true);
                }
                Array.Copy(block, 0, res_arr, i, block.Length);
            }
            return Encoding.Default.GetString(res_arr);
        }

        private static byte[] crypt_block(byte[] subblock_left_arr, byte[] subblock_right_arr, byte[] subblock_key_arr, bool isLast)
        {
            int subblock_left = BitConverter.ToInt32(subblock_left_arr, 0);
            int subblock_right = BitConverter.ToInt32(subblock_right_arr, 0);
            int subblock_key = BitConverter.ToInt32(subblock_key_arr, 0);

            subblock_left = subblock_left ^ subblock_key;
            subblock_left_arr = BitConverter.GetBytes(subblock_left);

            byte[] tmp = new byte[2];
            Array.Copy(subblock_left_arr, tmp, 2);
            Int16 left = BitConverter.ToInt16(tmp, 0);
            Array.Copy(subblock_left_arr, 2, tmp, 0, 2);
            Int16 right = BitConverter.ToInt16(subblock_left_arr, 2);

            subblock_right = f(left, right) ^ subblock_right;
            subblock_right_arr = BitConverter.GetBytes(subblock_right);

            byte[] res_arr = new byte[8];
            if (!isLast)
            {
                Array.Copy(subblock_right_arr, res_arr, 4);
                Array.Copy(subblock_left_arr, 0, res_arr, 4, 4);
            }
            else
            {
                Array.Copy(subblock_left_arr, res_arr, 4);
                Array.Copy(subblock_right_arr, 0, res_arr, 4, 4);
            }
            return res_arr;
        }

        public static string feistel_decrypt(string str, string key)
        {
            if (key.Length < 8)
                throw new ArgumentException("Very small key! (min = 8 symbols)");

            byte[] str_arr = Encoding.Default.GetBytes(str);
            byte[] key_arr = Encoding.Default.GetBytes(key);
            byte[] res_arr = new byte[str_arr.Length];

            int diff = str_arr.Length % 8;
            if (diff != 0)
                throw new ArgumentException("Incorrect input string!");
            for (int i = str_arr.Length - 8; i >= 0; i = i - 8)
            {
                byte[] block = new byte[8];
                Array.Copy(str_arr, i, block, 0, 8);
                for (int j = 9; j >= 0; j--)
                {

                    byte[] subblock_left_arr = new byte[4];
                    Array.Copy(block, subblock_left_arr, 4);
                    byte[] subblock_right_arr = new byte[4];
                    Array.Copy(block, 4, subblock_right_arr, 0, 4);

                    byte[] subblock_key_arr = new byte[4];
                    Array.Copy(key_arr, subblock_key_arr, 4);
                    subblock_key_arr = shift_key_left(key_arr, j);

                    if (j != 0)
                        block = decrypt_block(subblock_left_arr, subblock_right_arr, subblock_key_arr, false);
                    else
                        block = decrypt_block(subblock_left_arr, subblock_right_arr, subblock_key_arr, true);
                }

                Array.Copy(block, 0, res_arr, i, block.Length);
            }
            return Encoding.Default.GetString(res_arr);
        }

        private static byte[] decrypt_block(byte[] subblock_left_arr, byte[] subblock_right_arr, byte[] subblock_key_arr, bool isLast)
        {
            int subblock_left = BitConverter.ToInt32(subblock_left_arr, 0);
            int subblock_right = BitConverter.ToInt32(subblock_right_arr, 0);
            int subblock_key = BitConverter.ToInt32(subblock_key_arr, 0);

            byte[] tmp = new byte[2];
            Array.Copy(subblock_left_arr, tmp, 2);
            Int16 left = BitConverter.ToInt16(tmp, 0);
            Array.Copy(subblock_left_arr, 2, tmp, 0, 2);
            Int16 right = BitConverter.ToInt16(subblock_left_arr, 2);

            subblock_right = f(left, right) ^ subblock_right;

            subblock_left = subblock_left ^ subblock_key;
            subblock_left_arr = BitConverter.GetBytes(subblock_left);

            subblock_right_arr = BitConverter.GetBytes(subblock_right);

            byte[] res_arr = new byte[8];
            if (!isLast)
            {
                Array.Copy(subblock_right_arr, res_arr, 4);
                Array.Copy(subblock_left_arr, 0, res_arr, 4, 4);
            }
            else
            {
                Array.Copy(subblock_left_arr, res_arr, 4);
                Array.Copy(subblock_right_arr, 0, res_arr, 4, 4);
            }
            return res_arr;
        }

        private static int f(Int16 left, Int16 right)
        {
            int l = left << 7;
            int r = l >> 16;
            left = (Int16)(l + r);

            l = right >> 5;
            r = l << 11;
            right = (Int16)(l + r);

            int res = (int)left << 16;
            return res + right;
        }

        private static byte[] shift_key_left(byte[] key_arr, int i)
        {
            byte[] tmp = new byte[4];
            Array.Copy(key_arr, tmp, 4);
            int left = BitConverter.ToInt32(tmp, 0);
            Array.Copy(key_arr, 4, tmp, 0, 4);
            int right = BitConverter.ToInt32(tmp, 0);

            int l_l = left << (i * 3);
            int r_r = right >> (32 - i * 3);
            left = l_l + r_r;

            return BitConverter.GetBytes(left);
        }
        static void Main()
        {
            Console.WriteLine("Введите текст, который нужно зашифровать: ");
            string text = Console.ReadLine();
            Console.WriteLine("Введите ключ, который нужно зашифровать: ");
            string key = Console.ReadLine();
            string result = feistel_crypt(text,key);
            Console.WriteLine("Зашифрованное сообщение: {0}", result);
            Console.ReadLine();
            string res2 = feistel_decrypt(result,key);
            Console.WriteLine("Расшифрованное сообщение: {0}", res2);
        }
    }
}