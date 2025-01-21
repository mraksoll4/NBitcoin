using NBitcoin;
using NBitcoin.DataEncoders;
using System.Reflection;
using NBitcoin.Protocol;
using NBitcoin.RPC;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;

namespace NBitcoin.Altcoins
{
	public class Dpowcoin : NetworkSetBase
	{
		public static Dpowcoin Instance { get; } = new Dpowcoin();

		public override string CryptoCode => "DPC";

		private Dpowcoin()
		{

		}
		//Format visual studio
		//{({.*?}), (.*?)}
		//Tuple.Create(new byte[]$1, $2)
		static Tuple<byte[], int>[] pnSeed6_main =
			{
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x01,0xca,0x80,0xda}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x18,0x92,0x06,0x11}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x1f,0x1f,0x4f,0x86}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x25,0x3b,0x18,0x0f}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x25,0x61,0xa8,0xc8}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x25,0x8b,0x09,0xf8}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x26,0x6d,0xda,0x72}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x28,0x89,0x72}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x37,0xb0,0x1a}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x25,0x8b,0x09,0xf8}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x26,0x6d,0xda,0x72}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x28,0x89,0x72}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x37,0xb0,0x1a}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x25,0x8b,0x09,0xf8}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x26,0x6d,0xda,0x72}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x28,0x89,0x72}, 42003),
				Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x37,0xb0,0x1a}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xb8,0x16,0x6a,0xa1}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xa4,0x84,0xa9,0x05}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x3a,0xd6,0xe8,0x89}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x57,0xe5,0x54,0xb2}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xbc,0xf4,0x26,0x47}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x41,0x15,0x59,0xb6}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xcb,0xd2,0x1a,0x49}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x3d,0x27,0xe5,0x5e}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x6f,0x55,0xd0,0x3c}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2d,0x4e,0x06,0xec}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x05,0x19,0xa6,0x20}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x05,0x1b,0x1d,0x20}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x5f,0x18,0x52,0x3d}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x2e,0xad,0x95,0x5b}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x5f,0xd9,0x7a,0x1d}, 42003),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xb2,0xad,0x7f,0x70}, 42003)

			};
		static Tuple<byte[], int>[] pnSeed6_test =
			{
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0x5f,0xd9,0x7a,0x1d}, 42203),
                Tuple.Create(new byte[]{0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xff,0xff,0xb2,0xad,0x7f,0x70}, 42203)
			};
#pragma warning disable CS0618 // Type or member is obsolete
		public class DpowcoinConsensusFactory : ConsensusFactory
		{
			private DpowcoinConsensusFactory()
			{
			}

			public static DpowcoinConsensusFactory Instance { get; } = new DpowcoinConsensusFactory();

			public override BlockHeader CreateBlockHeader()
			{
				return new DpowcoinBlockHeader();
			}
			public override Block CreateBlock()
			{
				return new DpowcoinBlock(new DpowcoinBlockHeader());
			}
		}

		public class DpowcoinBlockHeader : BlockHeader
		{
			public override uint256 GetPoWHash()
			{
				var headerBytes = this.ToBytes();
				var h = NBitcoin.Crypto.SCrypt.ComputeDerivedKey(headerBytes, headerBytes, 1024, 1, 1, null, 32);
				return new uint256(h);
			}
		}

		public class DpowcoinBlock : Block
		{
			public DpowcoinBlock(DpowcoinBlockHeader header) : base(header)
			{

			}
			public override ConsensusFactory GetConsensusFactory()
			{
				return DpowcoinConsensusFactory.Instance;
			}
		}

		public class DpowcoinMainnetAddressStringParser : NetworkStringParser
		{
			public override bool TryParse(string str, Network network, Type targetType, out IBitcoinString result)
			{
				if(str.StartsWith("Ltpv", StringComparison.OrdinalIgnoreCase) && targetType.GetTypeInfo().IsAssignableFrom(typeof(BitcoinExtKey).GetTypeInfo()))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x88;
						decoded[2] = 0xAD;
						decoded[3] = 0xE4;
						result = new BitcoinExtKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{
					}
				}
				if(str.StartsWith("Ltub", StringComparison.OrdinalIgnoreCase) && targetType.GetTypeInfo().IsAssignableFrom(typeof(BitcoinExtPubKey).GetTypeInfo()))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x88;
						decoded[2] = 0xB2;
						decoded[3] = 0x1E;
						result = new BitcoinExtPubKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{
					}
				}
				return base.TryParse(str, network, targetType, out result);
			}
		}

		public class DpowcoinTestnetAddressStringParser : NetworkStringParser
		{
			public override bool TryParse(string str, Network network, Type targetType, out IBitcoinString result)
			{
				if (str.StartsWith("ttpv", StringComparison.OrdinalIgnoreCase) && targetType.GetTypeInfo().IsAssignableFrom(typeof(BitcoinExtKey).GetTypeInfo()))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x35;
						decoded[2] = 0x83;
						decoded[3] = 0x94;
						result = new BitcoinExtKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{
					}
				}
				if (str.StartsWith("ttub", StringComparison.OrdinalIgnoreCase) && targetType.GetTypeInfo().IsAssignableFrom(typeof(BitcoinExtPubKey).GetTypeInfo()))
				{
					try
					{
						var decoded = Encoders.Base58Check.DecodeData(str);
						decoded[0] = 0x04;
						decoded[1] = 0x35;
						decoded[2] = 0x87;
						decoded[3] = 0xCF;
						result = new BitcoinExtPubKey(Encoders.Base58Check.EncodeData(decoded), network);
						return true;
					}
					catch
					{
					}
				}
				return base.TryParse(str, network, targetType, out result);
			}
		}

#pragma warning restore CS0618 // Type or member is obsolete

		protected override void PostInit()
		{
			RegisterDefaultCookiePath("Dpowcoin", new FolderName() { TestnetFolder = "testnet4" });
		}

		protected override NetworkBuilder CreateMainnet()
		{
			NetworkBuilder builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 420000,
				MajorityEnforceBlockUpgrade = 750,
				MajorityRejectBlockOutdated = 950,
				MajorityWindow = 1000,
				BIP34Hash = new uint256(),
				PowLimit = new Target(new uint256("001fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(5 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(5 * 60),
				PowAllowMinDifficultyBlocks = false,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 6048,
				MinerConfirmationWindow = 8064,
				CoinbaseMaturity = 100,
				LitecoinWorkCalculation = true,
				ConsensusFactory = DpowcoinConsensusFactory.Instance,
				SupportSegwit = true
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 55 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 28 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 128 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x88, 0xB2, 0x1E })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x88, 0xAD, 0xE4 })
			.SetNetworkStringParser(new DpowcoinMainnetAddressStringParser())
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("dpc"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("dpc"))
			.SetMagic(0xfb4a9ff2)
			.SetPort(42003)
			.SetRPCPort(42002)
			.SetName("dpc-main")
			.AddAlias("dpc-mainnet")
			.AddAlias("dpowcoin-mainnet")
			.AddAlias("dpowcoin-main")
			.SetUriScheme("dpowcoin")
			.AddDNSSeeds(new[]
			{
				new DNSSeedData("seed.dpowcore.org", "seed.dpowcore.org"),
				new DNSSeedData("seed1.dpowcore.org", "seed1.dpowcore.org"),
				new DNSSeedData("seed2.dpowcore.org", "seed2.dpowcore.org"),
			})
			.AddSeeds(ToSeed(pnSeed6_main))
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000b38e51e3f65b6692f716de315ebb197333fb1596b80b54cf9a4469516e37f51070162266ffff1f1f8c6886000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff2804ffff001d0104204f6e6520504f573f20576879206e6f742074776f3f2031372f30342f32303234ffffffff0100f2052a01000000434104678afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4cef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateTestnet()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 420000,
				MajorityEnforceBlockUpgrade = 51,
				MajorityRejectBlockOutdated = 75,
				MajorityWindow = 1000,
				PowLimit = new Target(new uint256("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(5 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(5 * 60),
				PowAllowMinDifficultyBlocks = true,
				PowNoRetargeting = false,
				RuleChangeActivationThreshold = 1512,
				MinerConfirmationWindow = 2016,
				CoinbaseMaturity = 100,
				LitecoinWorkCalculation = true,
				ConsensusFactory = DpowcoinConsensusFactory.Instance,
				SupportSegwit = true
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 111 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 58 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x35, 0x87, 0xCF })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x35, 0x83, 0x94 })
			.SetNetworkStringParser(new DpowcoinTestnetAddressStringParser())
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("tltc"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("tltc"))
			.SetMagic(0xf1c8d2fd)
			.SetPort(19335)
			.SetRPCPort(19332)
			.SetName("ltc-test")
			.AddAlias("ltc-testnet")
			.AddAlias("litecoin-test")
			.AddAlias("litecoin-testnet")
			.SetUriScheme("litecoin")
			.AddDNSSeeds(new[]
			{
				new DNSSeedData("litecointools.com", "testnet-seed.litecointools.com"),
				new DNSSeedData("loshan.co.uk", "seed-b.litecoin.loshan.co.uk"),
				new DNSSeedData("thrasher.io", "dnsseed-testnet.thrasher.io"),
			})
			.AddSeeds(ToSeed(pnSeed6_test))
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97f60ba158f0ff0f1ee17904000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4804ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536ffffffff0100f2052a010000004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac00000000");
			return builder;
		}

		protected override NetworkBuilder CreateRegtest()
		{
			var builder = new NetworkBuilder();
			builder.SetConsensus(new Consensus()
			{
				SubsidyHalvingInterval = 150,
				MajorityEnforceBlockUpgrade = 51,
				MajorityRejectBlockOutdated = 75,
				MajorityWindow = 144,
				PowLimit = new Target(new uint256("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff")),
				PowTargetTimespan = TimeSpan.FromSeconds(3.5 * 24 * 60 * 60),
				PowTargetSpacing = TimeSpan.FromSeconds(2.5 * 60),
				PowAllowMinDifficultyBlocks = true,
				MinimumChainWork = uint256.Zero,
				PowNoRetargeting = true,
				RuleChangeActivationThreshold = 108,
				MinerConfirmationWindow = 2016,
				CoinbaseMaturity = 100,
				LitecoinWorkCalculation = true,
				ConsensusFactory = DpowcoinConsensusFactory.Instance,
				SupportSegwit = true
			})
			.SetBase58Bytes(Base58Type.PUBKEY_ADDRESS, new byte[] { 111 })
			.SetBase58Bytes(Base58Type.SCRIPT_ADDRESS, new byte[] { 58 })
			.SetBase58Bytes(Base58Type.SECRET_KEY, new byte[] { 239 })
			.SetBase58Bytes(Base58Type.EXT_PUBLIC_KEY, new byte[] { 0x04, 0x35, 0x87, 0xCF })
			.SetBase58Bytes(Base58Type.EXT_SECRET_KEY, new byte[] { 0x04, 0x35, 0x83, 0x94 })
			.SetBech32(Bech32Type.WITNESS_PUBKEY_ADDRESS, Encoders.Bech32("rltc"))
			.SetBech32(Bech32Type.WITNESS_SCRIPT_ADDRESS, Encoders.Bech32("rltc"))
			.SetMagic(0xdab5bffa)
			.SetPort(19444)
			.SetRPCPort(19443)
			.SetName("ltc-reg")
			.AddAlias("ltc-regtest")
			.AddAlias("litecoin-reg")
			.AddAlias("litecoin-regtest")
			.SetUriScheme("litecoin")
			.SetGenesis("010000000000000000000000000000000000000000000000000000000000000000000000d9ced4ed1130f7b7faad9be25323ffafa33232a17c3edf6cfd97bee6bafbdd97dae5494dffff7f20000000000101000000010000000000000000000000000000000000000000000000000000000000000000ffffffff4804ffff001d0104404e592054696d65732030352f4f63742f32303131205374657665204a6f62732c204170706c65e280997320566973696f6e6172792c2044696573206174203536ffffffff0100f2052a010000004341040184710fa689ad5023690c80f3a49c8f13f8d45b8c857fbcbc8bc4a8e4d3eb4b10f4d4604fa08dce601aaf0f470216fe1b51850b4acf21b179c45070ac7b03a9ac00000000");
			return builder;
		}
	}
}
