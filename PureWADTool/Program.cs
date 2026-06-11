using System;
using System.Collections.Generic;
using System.IO;
using System.IO.Compression;
using System.Text;

namespace PureWADTool
{
    class Program
    {
        const int SIG_SIZE = 256;
        static uint[] crcTable;

        class DlcKey
        {
            public string Name { get; set; }
            public uint[] KeyData { get; set; }
        }

        static void Main(string[] args)
        {
            Console.WriteLine("=============================================");
            Console.WriteLine("   WipEout Pure WAD Decryptor & Extractor    ");
            Console.WriteLine("=============================================\n");

            if (args.Length < 2 || args.Length > 3 || (args.Length == 3 && args[0].ToLower() != "-batch"))
            {
                Console.WriteLine("Usage: WipEoutWadTool.exe [ENCRYPTED_PI.WAD] [OUTPUT_DIRECTORY]");
                Console.WriteLine("       WipEoutWadTool.exe -batch [DLC_DIRECTORY] [OUTPUT_DIRECTORY]");
                Console.WriteLine("Ensure 'keys.txt' and 'filenames.txt' are in the executable directory.");
                return;
            }

            string keysFile = "keys.txt";
            string filenamesFile = "filenames.txt";

            if (!File.Exists(keysFile) || !File.Exists(filenamesFile))
            {
                Console.WriteLine("Error: Missing required files (keys.txt or filenames.txt).");
                return;
            }

            //Initialize CRC32 table
            InitializeCrc32();

            //Load keys & filenames once
            List<DlcKey> keys = ParseKeys(keysFile);
            Dictionary<uint, string> fileNamesMap = ParseFilenames(filenamesFile);
            Console.WriteLine($"Loaded {keys.Count} keys and {fileNamesMap.Count} known filenames.");

            //Batch mode processing
            if (args[0].ToLower() == "-batch")
            {
                string dlcDir = args[1];
                string outDir = args[2];

                if (!Directory.Exists(dlcDir))
                {
                    Console.WriteLine($"Error: DLC directory '{dlcDir}' does not exist.");
                    return;
                }

                string[] wadFiles = Directory.GetFiles(dlcDir, "PI.WAD", SearchOption.AllDirectories);
                Console.WriteLine($"Found {wadFiles.Length} PI.WAD files in '{dlcDir}'.\n");

                foreach (string wadFile in wadFiles)
                {
                    //Extract the name of the parent folder (e.g. "UCES00001DA7MUSIC")
                    string parentDirName = new DirectoryInfo(Path.GetDirectoryName(wadFile)).Name;
                    string specificOutDir = Path.Combine(outDir, parentDirName);

                    ProcessWad(wadFile, specificOutDir, keys, fileNamesMap);
                }
            }
            //Single file processing
            else
            {
                string sourceFile = args[0];
                string outDir = args[1];

                if (!File.Exists(sourceFile))
                {
                    Console.WriteLine($"Error: WAD file '{sourceFile}' does not exist.");
                    return;
                }

                ProcessWad(sourceFile, outDir, keys, fileNamesMap);
            }
        }

        static void ProcessWad(string sourceFile, string outDir, List<DlcKey> keys, Dictionary<uint, string> fileNamesMap)
        {
            Console.WriteLine($"\n=============================================");
            Console.WriteLine($"Processing: {sourceFile}");

            byte[] wadBytes = File.ReadAllBytes(sourceFile);
            uint initialVersion = BitConverter.ToUInt32(wadBytes, 0);

            if (initialVersion == 1)
            {
                Console.WriteLine("Detected an unencrypted WAD file. Skipping decryption phase...");
                ExtractWad(wadBytes, outDir, fileNamesMap);
                return;
            }

            DlcKey matchedKey = null;
            byte[] tryBytes = new byte[8];

            foreach (var key in keys)
            {
                Buffer.BlockCopy(wadBytes, 0, tryBytes, 0, 8);
                CryptWithKey(tryBytes, 8, key.KeyData);

                if (BitConverter.ToUInt32(tryBytes, 0) == 1) //WAD version = 1
                {
                    matchedKey = key;
                    break;
                }
            }

            if (matchedKey == null)
            {
                Console.WriteLine("Error: Could not identify key. WAD is invalid or missing from keys.txt.");
                return;
            }

            Console.WriteLine($"Detected Pack: {matchedKey.Name.Substring(10)} (Region: {matchedKey.Name[2]})");
            int payloadLength = wadBytes.Length - SIG_SIZE;
            Console.WriteLine($"Decrypting WAD payload... ({payloadLength} bytes)");

            //Decrypt the payload
            CryptWithKey(wadBytes, payloadLength, matchedKey.KeyData);

            //Extract and decompress
            ExtractWad(wadBytes, outDir, fileNamesMap);
        }

        static void ExtractWad(byte[] wadBytes, string outDir, Dictionary<uint, string> fileNamesMap)
        {
            using (MemoryStream ms = new MemoryStream(wadBytes))
            using (BinaryReader br = new BinaryReader(ms))
            {
                uint version = br.ReadUInt32();
                uint nfiles = br.ReadUInt32();

                if (version != 1)
                {
                    Console.WriteLine("Error: Invalid WAD header post-decryption.");
                    return;
                }

                Console.WriteLine($"WAD contains {nfiles} files. Extracting to '{outDir}'...\n");
                Console.WriteLine("OFFSET    NAMEHASH  METHOD  ORIG-SIZE -> COMP-SIZE  RATIO  FILENAME");
                Console.WriteLine("========  ========  ======  =========    =========  =====  ========");

                Directory.CreateDirectory(outDir);
                int knownCount = 0;

                for (int i = 0; i < nfiles; i++)
                {
                    //Seek to entry definition
                    ms.Seek(8 + (i * 16), SeekOrigin.Begin);
                    uint nameHash = br.ReadUInt32();
                    uint offset = br.ReadUInt32();
                    uint uncompressedLength = br.ReadUInt32();
                    uint compressedLength = br.ReadUInt32();

                    //Read payload
                    ms.Seek(offset, SeekOrigin.Begin);
                    byte[] fileData = br.ReadBytes((int)compressedLength);

                    //Determine Mode
                    string mode;
                    bool isZlib = (uncompressedLength & 0x80000000) != 0;
                    uint actualUncompressedLen = uncompressedLength & 0x7FFFFFFF;

                    if (actualUncompressedLen == compressedLength)
                        mode = "stored";
                    else if (isZlib)
                        mode = "zlib";
                    else
                        mode = "lzss";

                    //Decompress
                    byte[] uncompressedData = fileData;
                    if (mode == "lzss")
                        uncompressedData = DecompressLzss(fileData, (int)actualUncompressedLen);
                    else if (mode == "zlib")
                        uncompressedData = DecompressZlib(fileData, (int)actualUncompressedLen);

                    //Resolve filename
                    string filename = fileNamesMap.ContainsKey(nameHash)
                        ? fileNamesMap[nameHash]
                        : $"data/unknown/{nameHash:x8}.raw";

                    if (!filename.Contains("unknown")) knownCount++;

                    //Console output
                    string ratio = mode != "stored" ? $"{100.0 * compressedLength / actualUncompressedLen,3:F0}%" : " ---";
                    Console.WriteLine($"{offset:x8}  {nameHash:x8}  {mode,-6}  {actualUncompressedLen,8}     {compressedLength,8}   {ratio}  {filename}");

                    //Save to disk
                    string fullPath = Path.Combine(outDir, filename.Replace('/', Path.DirectorySeparatorChar));
                    Directory.CreateDirectory(Path.GetDirectoryName(fullPath));
                    File.WriteAllBytes(fullPath, uncompressedData);
                }

                Console.WriteLine($"\nExtraction Complete! {knownCount}/{nfiles} filenames resolved.");
            }
        }

        static void Xtea8(uint[] genkey, uint[] key)
        {
            uint v0 = genkey[0];
            uint v1 = genkey[1];
            uint k = 0x9e3779b9;
            uint num_rounds = 8;
            uint sum = 0;

            for (uint i = 0; i < num_rounds; ++i)
            {
                v0 += (((v1 << 4 ^ v1 >> 5) + v1) ^ (key[sum & 3] + sum));
                sum += k;
                v1 += (((v0 << 4 ^ v0 >> 5) + v0) ^ (key[(sum >> 11) & 3] + sum));
            }
            genkey[0] = v0;
            genkey[1] = v1;
        }

        static void CryptWithKey(byte[] buffer, int bufferLength, uint[] key)
        {
            uint[] genkey32 = new uint[2];
            byte[] genkey8 = new byte[8];

            for (int i = 0; i < bufferLength; ++i)
            {
                if (i % 8 == 0)
                {
                    genkey32[0] = 0x12345678;
                    genkey32[1] = (uint)(i / 8);
                    Xtea8(genkey32, key);
                    Buffer.BlockCopy(genkey32, 0, genkey8, 0, 8);
                }
                buffer[i] ^= genkey8[i % 8];
            }
        }

        static byte[] DecompressLzss(byte[] input, int uncompressedSize)
        {
            byte[] output = new byte[uncompressedSize];
            int outPos = 0, inBytePos = 0, bitPos = 0;
            byte[] lookback = new byte[0x2000];
            int lookbackPos = 1;

            int ReadBits(int n)
            {
                int val = 0;
                for (int i = 0; i < n; i++)
                {
                    int b = (input[inBytePos] & (1 << (7 - bitPos))) != 0 ? 1 : 0;
                    bitPos++;
                    if (bitPos == 8) { bitPos = 0; inBytePos++; }
                    val = (val << 1) | b;
                }
                return val;
            }

            while (outPos < uncompressedSize)
            {
                if (ReadBits(1) == 1) //Verbatim
                {
                    byte b = (byte)ReadBits(8);
                    output[outPos++] = b;
                    lookback[lookbackPos] = b;
                    lookbackPos = (lookbackPos + 1) & 0x1fff;
                }
                else //Copy
                {
                    int offset = ReadBits(13);
                    int count = 3 + ReadBits(4);
                    for (int i = 0; i < count; i++)
                    {
                        if (outPos >= uncompressedSize) break;
                        byte b = lookback[(offset + i) & 0x1fff];
                        output[outPos++] = b;
                        lookback[lookbackPos] = b;
                        lookbackPos = (lookbackPos + 1) & 0x1fff;
                    }
                }
            }
            return output;
        }

        static byte[] DecompressZlib(byte[] input, int uncompressedSize)
        {
            //Skip 2-byte zlib header to use .NET's DeflateStream
            using (var ms = new MemoryStream(input, 2, input.Length - 2))
            using (var deflate = new DeflateStream(ms, CompressionMode.Decompress))
            using (var outMs = new MemoryStream())
            {
                deflate.CopyTo(outMs);
                return outMs.ToArray();
            }
        }

        static void InitializeCrc32()
        {
            crcTable = new uint[256];
            uint poly = 0xEDB88320;
            for (uint i = 0; i < 256; i++)
            {
                uint crc = i;
                for (int j = 8; j > 0; j--)
                {
                    if ((crc & 1) == 1) crc = (crc >> 1) ^ poly;
                    else crc >>= 1;
                }
                crcTable[i] = crc;
            }
        }

        static uint Crc32(string input)
        {
            uint crc = 0x00000000;

            byte[] bytes = Encoding.UTF8.GetBytes(input);
            foreach (byte b in bytes)
            {
                crc = (crc >> 8) ^ crcTable[(crc & 0xFF) ^ b];
            }

            return crc ^ 0xFFFFFFFF;
        }

        static Dictionary<uint, string> ParseFilenames(string filePath)
        {
            var map = new Dictionary<uint, string>();
            foreach (var line in File.ReadAllLines(filePath))
            {
                string cleanLine = line.Trim().Replace('\\', '/').ToLower();
                if (string.IsNullOrWhiteSpace(cleanLine)) continue;
                map[Crc32(cleanLine)] = cleanLine;
            }
            return map;
        }

        static List<DlcKey> ParseKeys(string filePath)
        {
            var keyList = new List<DlcKey>();
            foreach (string line in File.ReadAllLines(filePath))
            {
                string trimmed = line.Trim();
                if (string.IsNullOrWhiteSpace(trimmed) || trimmed.StartsWith("#")) continue;

                string[] parts = trimmed.Split(new char[] { ' ', '\t' }, StringSplitOptions.RemoveEmptyEntries);
                if (parts.Length == 17)
                {
                    var dlcKey = new DlcKey { Name = parts[0], KeyData = new uint[4] };
                    byte[] keyBytes = new byte[16];
                    for (int i = 0; i < 16; i++) keyBytes[i] = Convert.ToByte(parts[i + 1], 16);
                    Buffer.BlockCopy(keyBytes, 0, dlcKey.KeyData, 0, 16);
                    keyList.Add(dlcKey);
                }
            }
            return keyList;
        }
    }
}