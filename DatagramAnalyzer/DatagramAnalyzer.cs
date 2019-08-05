using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

using System.Runtime.InteropServices;
using System.Text.RegularExpressions;
using CustomCollections;
using System.Diagnostics;

namespace SerialPortVisuanalyzer
{
	public class DatagramAnalyzer
	{
		// 変数の情報を格納しておく
		public class VariableInfo
		{
			public string Name { get; }
			public Type VarType { get; }
			public int BitSize { get; }
			public int BitIndex { get; }
			public bool IsFixed { get; }
			public byte[] FixedValues { get; }

			public int ByteIndexFrom { get => BitIndex / 8; }
			public int ByteIndexUntil { get => (BitIndex + BitSize - 1) / 8; }

			public byte[] RawByteArray { get; private set; }
			public byte[] AlignedByteArray { get; private set; }

			public object Value { get; private set; }

            public VariableInfo(string Name, Type VarType, int BitSize, int BitIndex, bool IsFixed = false, string HexString = "")
            {
                string errormsg = "";
                if (VarType == null) errormsg += "VariableType" + ",Type must be selected.\r\n";
                if (Name == null) errormsg += "VariableName" + ",Name must be exists.\r\n";
                else if (Name.Length == 0) errormsg += "VariableName" + ",Name must be exists.\r\n";
                if (BitSize <= 0) errormsg += "VariableSize" + ",Size must be more than 0.\r\n";

                byte[] FixedValues = null;
                if(IsFixed)
                {
                    if(HexString == null)
                        errormsg += "FixedValue" + ",The number of hexadecimal digits does not match the type size.\r\n";
                    else if (!IsHexString(HexString))
                        errormsg += "FixedValue" + ",Do not enter anything other than 0~9 and A~F.\r\n";
                    else if (HexString.Length != Marshal.SizeOf(VarType) * 2)
                        errormsg += "Fixedvalue" + ",The number of hexadecimal digits does not match the type size.\r\n";
					if (BitSize % 8 != 0)
                        errormsg += "VariableSize" + ",BitSize of 'Fixed value packet' must be a multiple of 8.\r\n";
					if (BitIndex % 8 != 0)
                        errormsg += "VariableIndex" + ",BitIndex of 'Fixed value packet' must be a multiple of 8. Please add padding packets.\r\n";
                }

                if (errormsg.Length != 0)
                    throw new FormatException(errormsg);

                if(IsFixed)
					FixedValues = Regex.Split(HexString, @"(?<=\G.{2})(?!$)").Select(hs => Convert.ToByte(hs, 16)).ToArray();

                this.Name = Name;
                this.VarType = VarType;
                this.BitSize = BitSize;
                this.BitIndex = BitIndex;
                this.IsFixed = IsFixed;
                this.FixedValues = FixedValues ?? new byte[0];
                RawByteArray = new byte[ByteIndexUntil - ByteIndexFrom + 1];
                AlignedByteArray = new byte[(int)Math.Ceiling((double)BitSize / 8)];
            }

			public void Align(byte[] rawBytes)
			{
				if (RawByteArray.Length != rawBytes.Length)
					throw new ArgumentOutOfRangeException("VariableInfo.Align()", "Invalied rawBytes.Length");
				Array.Copy(rawBytes, RawByteArray, RawByteArray.Length);
				for (int i = 0; i < AlignedByteArray.Length; i++)
				{
					if (i + 1 == RawByteArray.Length)
						AlignedByteArray[i] = (byte)((RawByteArray[i] >> (BitIndex % 8)) & (0xFF >> ((BitSize % 8 == 0) ? 0 :(8 - BitSize % 8))));
					else
					{
						if (i + 1 == AlignedByteArray.Length)
							AlignedByteArray[i] = (byte)((byte)((RawByteArray[i + 1] << (8 - (BitIndex) % 8)) & (0xFF >> ((BitSize % 8 == 0) ? 0 : (8 - BitSize % 8)))) + (byte)(RawByteArray[i] >> (BitIndex % 8)));
						else
							AlignedByteArray[i] = (byte)((byte)(RawByteArray[i + 1] << (8 - (BitIndex) % 8)) + (byte)(RawByteArray[i] >> (BitIndex % 8)));
					}
                    switch(this.VarType.Name)
                    {
                        case nameof(Char  ):
                            this.Value = (char)AlignedByteArray[0];
                            break;
                        case nameof(Byte  ):
                            this.Value = AlignedByteArray[0];
                            break;
                        case nameof(SByte ):
                            this.Value = (SByte)AlignedByteArray[0];
                            break;
                        case nameof(UInt16):
                            var resUI16 = new UInt16[1];
                            Buffer.BlockCopy(AlignedByteArray, 0, resUI16, 0, AlignedByteArray.Length);
                            this.Value = resUI16[0];
                            break;
                        case nameof(Int16 ):
                            var resI16 = new Int16[1];
                            Buffer.BlockCopy(AlignedByteArray, 0, resI16, 0, AlignedByteArray.Length);
                            this.Value = resI16[0];
                            break;
                        case nameof(UInt32):
                            var resUI32 = new UInt32[1];
                            Buffer.BlockCopy(AlignedByteArray, 0, resUI32, 0, AlignedByteArray.Length);
                            this.Value = resUI32[0];
                            break;
                        case nameof(Int32 ):
                            var resI32 = new Int32[1];
                            Buffer.BlockCopy(AlignedByteArray, 0, resI32, 0, AlignedByteArray.Length);
                            this.Value = resI32[0];
                            break;
                        case nameof(UInt64):
                            var resUI64 = new UInt64[1];
                            Buffer.BlockCopy(AlignedByteArray, 0, resUI64, 0, AlignedByteArray.Length);
                            this.Value = resUI64[0];
                            break;
                        case nameof(Int64 ):
                            var resI64 = new UInt64[1];
                            Buffer.BlockCopy(AlignedByteArray, 0, resI64, 0, AlignedByteArray.Length);
                            this.Value = resI64[0];
                            break;
                        case nameof(Single):
                            var resS = new Single[1];
                            Buffer.BlockCopy(AlignedByteArray, 0, resS, 0, AlignedByteArray.Length);
                            this.Value = resS[0];
                            break;
                        case nameof(Double):
                            var resD = new Double[1];
                            Buffer.BlockCopy(AlignedByteArray, 0, resD, 0, AlignedByteArray.Length);
                            this.Value = resD[0];
                            break;
                        default:
                            break;
                    }
				}
			}

			public override string ToString()
			{
                var res = $"{Name} -> {Convert.ChangeType(Value ?? 0, VarType)} / {VarType.Name} index:{BitIndex} size:{BitSize}bit";
				if (IsFixed)
				{
					res += $" Hex:{string.Join("", FixedValues.Select(b => String.Format("{0:X2} ", b)))}";
				}
				else
				{
					//res += $" Raw:{string.Join("", RawByteArray.Select(b => String.Format("{0:X2} ", b)))}";
					res += $" Hex:{string.Join("", AlignedByteArray.Select(b => String.Format("{0:X2} ", b)))}";
				}
                return res;
			}
		}

		// 1バイト単位の情報を格納しておく
		public class PacketInfo : System.IEquatable<PacketInfo>
		{
			public byte Value { get; set; }
			public bool IsFixed { get; }
			public byte FixedValue { get; }

			public PacketInfo() : this(false, 0x00) { }

			public PacketInfo(bool IsFixed) : this(IsFixed, 0x00) { }

			public PacketInfo(bool IsFixed, byte FixedValue)
			{
				this.IsFixed = IsFixed;
				this.FixedValue = FixedValue;
				this.Value = 0x00;
			}

			public bool Equals(PacketInfo pi)
			{
				if (pi == null)
					return false;
				return this.IsFixed == pi.IsFixed;
				// return (this.IsFixed == pi.IsFixed) && (this.FixedValue == pi.FixedValue) && (this.Value == pi.Value);
			}

			public override bool Equals(object obj)
			{
				if (obj == null || this.GetType() != obj.GetType())
					return false;
				return this.IsFixed == ((PacketInfo)obj).IsFixed;
				// var pi = (PacketInfo)obj;
				// return (this.IsFixed == pi.IsFixed) && (this.FixedValue == pi.FixedValue) && (this.Value == pi.Value);
			}

			public override int GetHashCode()
			{
				return this.IsFixed.GetHashCode();
			}

			public override string ToString()
			{
				return $"Value:{String.Format("{0:X2}", this.Value)}  IsFixed:{this.IsFixed}  FixedValue:{String.Format("{0:X2}", this.FixedValue)}";
			}
		}

		public bool IsReady { get; private set; }
		public bool Updated { get; private set; }
		public List<VariableInfo> VariableInfos { get; private set; }
		public List<PacketInfo> PacketInfos { get; private set; }
		public CircularBuffer<byte> PacketBuffer { get; private set; }
		
		public DatagramAnalyzer()
		{
			IsReady = false;
			VariableInfos = new List<VariableInfo>();
			PacketInfos = new List<PacketInfo>();
		}

		public void Clear()
		{
			IsReady = false;
			VariableInfos.Clear();
			PacketInfos.Clear();
		}

		public void SetVariableInfo(VariableInfo vi)
		{
			IsReady = false;
			VariableInfos.Add(vi);
		}

		public void Verify()
		{
            // VariableInfosをPacketInfoに整形
            bool fixedPacketExists = false;
            foreach (var vi in VariableInfos)
			{
				if (!vi.IsFixed)
				{
					while (PacketInfos.Count <= vi.ByteIndexUntil)
						PacketInfos.Add(new PacketInfo());
				}
				else
				{
					foreach(var b in vi.FixedValues)
						PacketInfos.Add(new PacketInfo(true, b));
                    fixedPacketExists = true;
                }
			}
            if (!fixedPacketExists) throw new FormatException("One or more fixed value packet must be specified");
			IsReady = true;
			PacketBuffer = new CircularBuffer<byte>(PacketInfos.Count * 3);
			Debug.WriteLine($"\r\nVariables Infomation  Count:{VariableInfos.Count}");
			foreach (var vi in VariableInfos) Console.WriteLine(vi.ToString());
			Debug.WriteLine($"\r\nPackets Infomation  Count:{PacketInfos.Count}");
			foreach (var pi in PacketInfos) Console.WriteLine(pi.ToString());
			Debug.WriteLine($"\r\nCircular buffer Capacity:{PacketBuffer.Capacity}");
		}

        public void Enqueue(byte b)
        {
            if(IsReady)
                PacketBuffer.Enqueue(b);
        }

		public void Update()
		{
			if (IsReady)
			{
				Updated = false;
				for (int bufferIndex = -1; bufferIndex >= -PacketBuffer.Count && !Updated; --bufferIndex)  // リングバッファ内を走査
				{
                    //Console.WriteLine($"PacketInfos.IndexOf(new PacketInfo(true)):{PacketInfos.IndexOf(new PacketInfo(true))} <= bufferIndex:{bufferIndex} + PacketBuffer.Count:{PacketBuffer.Count}" +
                    //                  $" && (PacketInfos.Count:{PacketInfos.Count} - PacketInfos.LastIndexOf(new PacketInfo(true)):{PacketInfos.LastIndexOf(new PacketInfo(true))} <= -bufferIndex:{-bufferIndex})");
					if ((PacketInfos.IndexOf(new PacketInfo(true)) <= bufferIndex + PacketBuffer.Count) && (PacketInfos.Count - PacketInfos.LastIndexOf(new PacketInfo(true)) <= -bufferIndex))  // 固定値の位置をもとに，データグラムがバッファを超えないかを判別
					{
						if (PacketInfos[PacketInfos.LastIndexOf(new PacketInfo(true))].FixedValue == PacketBuffer[bufferIndex])    // 固定値合致判別
						{
							//Console.WriteLine($"packetindex:{bufferIndex + (PacketInfos.Count - PacketInfos.LastIndexOf(new PacketInfo(true)) + 1)}");
							for (int datagramIndex = 0, packetIndex = bufferIndex + (PacketInfos.Count - PacketInfos.LastIndexOf(new PacketInfo(true)) + 1);
								datagramIndex < PacketInfos.Count;
								++datagramIndex, packetIndex++) // PacketInfosに転写
							{
								if (PacketInfos[datagramIndex].IsFixed && PacketInfos[datagramIndex].FixedValue != PacketBuffer[packetIndex])
								{
									break; // 固定値不一致
								}
								else
								{
									PacketInfos[datagramIndex].Value = PacketBuffer[packetIndex];
									if (datagramIndex + 1 == PacketInfos.Count)
										Updated = true;
								}
							}
						}
					}
				}
				if (Updated)
				{
					foreach (var vi in VariableInfos)	// PacketInfosからVariableInfosへ転写
					{
						vi.Align(PacketInfos.Where((pi, index) => (vi.ByteIndexFrom <= index) && (index <= vi.ByteIndexUntil))
											.Select(pi => pi.Value).ToArray());
                        Debug.WriteLine(vi.ToString());
					}
                    Debug.WriteLine("");
				}
			}
		}

		public override string ToString()
		{
			string res = "";
			foreach (var vi in VariableInfos)
				res += vi.ToString() + Environment.NewLine;
			Updated = false;
			return res;
		}

        public static bool IsHexString(string str)
        {
            if (str == null) return false;
            if (str.Length == 0) return false;
            foreach (var s in str)
            {
                if ((s < '0' || '9' < s)
                    && (s < 'A' || 'F' < s)
                    && (s < 'a' || 'f' < s))
                    return false;
            }
            return true;
        }
    }
}
