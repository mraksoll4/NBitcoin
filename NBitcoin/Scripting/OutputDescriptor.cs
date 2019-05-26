using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using NBitcoin.Crypto;
using NBitcoin.Scripting.Parser;

namespace NBitcoin.Scripting
{

	public abstract class OutputDescriptor : IEquatable<OutputDescriptor>
	{
		# region subtypes
		public static class Tags
		{
			public const int AddressDescriptor = 0;
			public const int RawDescriptor = 1;
			public const int PKDescriptor = 2;
			public const int ExtPubKeyOutputDescriptor = 3;
			public const int PKHDescriptor = 4;
			public const int WPKHDescriptor = 5;
			public const int ComboDescriptor = 6;
			public const int MultisigDescriptor = 7;
			public const int SHDescriptor = 8;
			public const int WSHDescriptor = 9;
		}

		public class AddressDescriptor : OutputDescriptor
		{
			public IDestination Address { get; }
			public AddressDescriptor(IDestination address) : base(Tags.AddressDescriptor)
			{
				if (address == null)
					throw new ArgumentNullException(nameof(address));
				Address = address;
			}
		}

		public class RawDescriptor : OutputDescriptor
		{
			public Script Script;

			internal RawDescriptor(Script script) : base(Tags.RawDescriptor) => Script = script ?? throw new ArgumentNullException(nameof(script));
		}

		public class PKDescriptor : OutputDescriptor
		{
			public PubKeyProvider PkProvider;
			internal PKDescriptor(PubKeyProvider pkProvider) : base(Tags.PKDescriptor)
			{
				if (pkProvider == null)
					throw new ArgumentNullException(nameof(pkProvider));
				PkProvider = pkProvider;
			}
		}

		public class PKHDescriptor : OutputDescriptor
		{
			public PubKeyProvider PkProvider;
			internal PKHDescriptor(PubKeyProvider pkProvider) : base(Tags.PKHDescriptor)
			{
				if (pkProvider == null)
					throw new ArgumentNullException(nameof(pkProvider));
				PkProvider = pkProvider;
			}
		}

		public class WPKHDescriptor : OutputDescriptor
		{
			public PubKeyProvider PkProvider;
			internal WPKHDescriptor(PubKeyProvider pkProvider) : base(Tags.WPKHDescriptor)
			{
				if (pkProvider == null)
					throw new ArgumentNullException(nameof(pkProvider));
				PkProvider = pkProvider;
			}
		}
		public class ComboDescriptor : OutputDescriptor
		{
			public PubKeyProvider PkProvider;
			internal ComboDescriptor(PubKeyProvider pkProvider) : base(Tags.ComboDescriptor)
			{
				if (pkProvider == null)
					throw new ArgumentNullException(nameof(pkProvider));
				PkProvider = pkProvider;
			}
		}

		public class MultisigDescriptor : OutputDescriptor
		{
			public List<PubKeyProvider> PkProviders;
			internal MultisigDescriptor(uint threshold, IEnumerable<PubKeyProvider> pkProviders) : base(Tags.MultisigDescriptor)
			{
				if (pkProviders == null)
					throw new ArgumentNullException(nameof(pkProviders));
				PkProviders = pkProviders.ToList();
				if (PkProviders.Count == 0)
					throw new ArgumentException("Multisig Descriptor can not have empty pubkey providers");
				Threshold = threshold;
			}

			public uint Threshold { get; }
		}

		public class SHDescriptor : OutputDescriptor
		{
			public OutputDescriptor Inner;
			internal SHDescriptor(OutputDescriptor inner) : base(Tags.SHDescriptor)
			{
				if (inner == null)
					throw new ArgumentNullException(nameof(inner));
				if (inner.IsTopLevelOnly())
					throw new ArgumentException($"{inner} can not be inner element for SHDescriptor");
				Inner = inner;
			}
		}

		public class WSHDescriptor : OutputDescriptor
		{
			public OutputDescriptor Inner;
			internal WSHDescriptor(OutputDescriptor inner) : base(Tags.WSHDescriptor)
			{
				if (inner == null)
					throw new ArgumentNullException(nameof(inner));
				if (inner.IsTopLevelOnly() || inner.IsWSH())
					throw new ArgumentException($"{inner} can not be inner element for WSHDescriptor");
				Inner = inner;
			}
		}

		internal int Tag { get; }
		private OutputDescriptor(int tag)
		{
			Tag = tag;
		}

		public static OutputDescriptor NewAddr(IDestination dest) => new AddressDescriptor(dest);
		public static OutputDescriptor NewRaw(Script sc) => new RawDescriptor(sc);
		public static OutputDescriptor NewPK(PubKeyProvider pk) => new PKDescriptor(pk);
		public static OutputDescriptor NewPKH(PubKeyProvider pk) => new PKHDescriptor(pk);
		public static OutputDescriptor NewWPKH(PubKeyProvider pk) => new WPKHDescriptor(pk);
		public static OutputDescriptor NewCombo(PubKeyProvider pk) => new ComboDescriptor(pk);
		public static OutputDescriptor NewMulti(uint m, IEnumerable<PubKeyProvider> pks) => new MultisigDescriptor(m, pks);

		public static OutputDescriptor NewSH(OutputDescriptor inner) => new SHDescriptor(inner);
		public static OutputDescriptor NewWSH(OutputDescriptor inner) => new WSHDescriptor(inner);

		public bool IsAddr() => Tag == Tags.AddressDescriptor;
		public bool IsRaw() => Tag == Tags.RawDescriptor;
		public bool IsPK() => Tag == Tags.PKDescriptor;
		public bool IsPKH() => Tag == Tags.PKHDescriptor;
		public bool IsWPKH() => Tag == Tags.WPKHDescriptor;
		public bool IsCombo() => Tag == Tags.ComboDescriptor;
		public bool IsMulti() => Tag == Tags.MultisigDescriptor;
		public bool IsSH() => Tag == Tags.SHDescriptor;
		public bool IsWSH() => Tag == Tags.WSHDescriptor;

		public bool IsTopLevelOnly() =>
			IsAddr() || IsRaw() || IsCombo() || IsSH();

		#endregion

		#region Descriptor specific things
		/// <summary>
		/// Expand descriptor into actual scriptPubKeys.
		/// TODO: cache
		/// </summary>
		/// <param name="pos">position index to expand</param>
		/// <param name="privateKeyProvider">provider to inject private keys in case of hardened derivation</param>
		/// <param name="outputScripts">resulted scriptPubKey</param>
		/// <returns></returns>
		public bool TryExpand(
			uint pos,
			Func<KeyId, Key> privateKeyProvider,
			out FlatSigningRepository repo,
			out List<Script> outputScripts
			)
		{
			outputScripts = new List<Script>();
			repo = new FlatSigningRepository();
			return TryExpand(pos, privateKeyProvider, repo, outputScripts);
		}

		private bool ExpandPkHelper(
			PubKeyProvider pkP,
			Func<KeyId, Key> privateKeyProvider,
			uint pos,
			FlatSigningRepository repo,
			List<Script> outSc)
		{
			if (!pkP.TryGetPubKey(pos, privateKeyProvider, out var keyOrigin1, out var pubkey1))
				return false;
			if (keyOrigin1 != null)
				repo.SetKeyOrigin(pubkey1.Hash, keyOrigin1);
			repo.SetPubKey(pubkey1.Hash, pubkey1);
			outSc.AddRange(MakeScripts(pubkey1, repo));
			return true;
		}
		private bool TryExpand(
			uint pos,
			Func<KeyId, Key> privateKeyProvider,
			FlatSigningRepository repo,
			List<Script> outputScripts
			)
		{
			switch (this)
			{
				case AddressDescriptor self:
					return false;
				case RawDescriptor self:
					return false;
				case PKDescriptor self:
					return ExpandPkHelper(self.PkProvider, privateKeyProvider, pos, repo, outputScripts);
				case PKHDescriptor self:
					return ExpandPkHelper(self.PkProvider, privateKeyProvider, pos, repo, outputScripts);
				case WPKHDescriptor self:
					return ExpandPkHelper(self.PkProvider, privateKeyProvider, pos, repo, outputScripts);
				case ComboDescriptor self:
					return ExpandPkHelper(self.PkProvider, privateKeyProvider, pos, repo, outputScripts);
				case MultisigDescriptor self:
					// prepare temporary objects so that it won't affect the result in case
					// it fails in the middle.
					var tmpRepo = new FlatSigningRepository();
					var keys = new PubKey[self.PkProviders.Count];
					for (int i = 0; i < self.PkProviders.Count; ++i)
					{
						var pkP = self.PkProviders[i];
						if (!pkP.TryGetPubKey(pos, privateKeyProvider, out var keyOrigin1, out var pubkey1))
							return false;
						if (keyOrigin1 != null)
							tmpRepo.SetKeyOrigin(pubkey1.Hash, keyOrigin1);
						tmpRepo.SetPubKey(pubkey1.Hash, pubkey1);
						keys[i] = pubkey1;
					}
					repo = repo.Merge(tmpRepo);
					outputScripts.Add(PayToMultiSigTemplate.Instance.GenerateScriptPubKey((int)self.Threshold, keys));
					return true;
				case SHDescriptor self:
					if (!self.Inner.TryExpand(pos, privateKeyProvider, out var subRepo1, out var shInnerResult))
						return false;
					repo = repo.Merge(subRepo1);
					foreach (var inner in shInnerResult)
					{
						repo.SetScript(inner.Hash, inner);
						outputScripts.Add(inner.Hash.ScriptPubKey);
					}
					return true;
				case WSHDescriptor self:
					if (!self.Inner.TryExpand(pos, privateKeyProvider, out var subRepo2, out var wshInnerResult))
						return false;
					repo = repo.Merge(subRepo2);
					foreach (var inner in wshInnerResult)
					{
						repo.SetScript(inner.Hash, inner);
						repo.SetScript(inner.WitHash.HashForLookUp, inner);
						outputScripts.Add(inner.WitHash.ScriptPubKey);
					}
					return true;
			}
			throw new Exception("Unreachable");
		}

		private List<Script> MakeScripts(PubKey key, ISigningRepository repo)
		{
			switch (this)
			{
				case AddressDescriptor self:
					return new List<Script>() { self.Address.ScriptPubKey };
				case RawDescriptor self:
					return new List<Script>() { self.Script };
				case PKDescriptor self:
					return new List<Script>() { key.ScriptPubKey };
				case PKHDescriptor self:
					return new List<Script>() { key.Hash.ScriptPubKey };
				case WPKHDescriptor self:
					return new List<Script>() { key.WitHash.ScriptPubKey };
				case ComboDescriptor self:
					var res = new List<Script>()
					{
						key.ScriptPubKey,
						key.Hash.ScriptPubKey,
					};
					if (key.IsCompressed)
					{
						res.Add(key.WitHash.ScriptPubKey);
						res.Add(key.WitHash.ScriptPubKey.Hash.ScriptPubKey);
						repo.SetScript(key.WitHash.ScriptPubKey.Hash, key.WitHash.ScriptPubKey);
					}
					return res;
			}

			throw new Exception("Unreachable");
		}

		public bool IsSolvable()
		{
			switch (this.Tag)
			{
				case Tags.AddressDescriptor:
				case Tags.RawDescriptor:
					return false;
				case Tags.SHDescriptor:
					return ((SHDescriptor)this).Inner.IsSolvable();
				case Tags.WSHDescriptor:
					return ((WSHDescriptor)this).Inner.IsSolvable();
				default:
					return true;
			}
		}

		public bool IsRange()
		{
			switch (this)
			{
				case AddressDescriptor _:
					return false;
				case RawDescriptor _:
					return false;
				case PKDescriptor self:
					return self.PkProvider.IsRange();
				case PKHDescriptor self:
					return self.PkProvider.IsRange();
				case WPKHDescriptor self:
					return self.PkProvider.IsRange();
				case ComboDescriptor self:
					return self.PkProvider.IsRange();
				case MultisigDescriptor self:
					return self.PkProviders.Any(pk => pk.IsRange());
				case SHDescriptor self:
					return self.Inner.IsRange();
				case WSHDescriptor self:
					return self.Inner.IsRange();
			}
			throw new Exception("Unreachable");
		}

		public enum ScriptContext
		{
			TOP,
			P2SH,
			P2WSH
		}

		private static PubKeyProvider InferPubKey(PubKey pk, ISigningRepository repo,ScriptContext ctx)
		{
			var keyProvider = PubKeyProvider.NewConst(pk);
			if (repo.TryGetKeyOrigin(pk.Hash, out var keyOrigin))
			{
				return PubKeyProvider.NewOrigin(keyOrigin, keyProvider);
			}
			return keyProvider;
		}

		public static OutputDescriptor InferFromScript(Script sc, ISigningRepository repo, ScriptContext ctx = ScriptContext.TOP)
		{
			var template = sc.FindTemplate();
			if (template is PayToPubkeyTemplate p2pkTemplate)
			{
				var pk = p2pkTemplate.ExtractScriptPubKeyParameters(sc);
				return OutputDescriptor.NewPK(InferPubKey(pk, repo, ctx));
			}
			if (template is PayToPubkeyHashTemplate p2pkhTemplate)
			{
				var pkHash = p2pkhTemplate.ExtractScriptPubKeyParameters(sc);
				if (repo.TryGetPubKey(pkHash, out var pk))
					return OutputDescriptor.NewPKH(InferPubKey(pk, repo, ctx));
			}
			if (template is PayToMultiSigTemplate p2MultiSigTemplate)
			{
				var providers = new List<PubKeyProvider>();
				var data = p2MultiSigTemplate.ExtractScriptPubKeyParameters(sc);
				foreach (var pk in data.PubKeys)
				{
					providers.Add(InferPubKey(pk, repo, ctx));
				}
				return OutputDescriptor.NewMulti((uint)data.SignatureCount, providers);
			}
			if (template is PayToScriptHashTemplate p2shTemplate && ctx == ScriptContext.TOP)
			{
				var scriptId = p2shTemplate.ExtractScriptPubKeyParameters(sc);
				if (repo.TryGetScript(scriptId, out var nextScript))
				{
					var sub = InferFromScript(nextScript, repo, ScriptContext.P2SH);
					return OutputDescriptor.NewSH(sub);
				}
			}
			if (template is PayToWitTemplate)
			{
				var witScriptId = PayToWitScriptHashTemplate.Instance.ExtractScriptPubKeyParameters(sc);
				if (witScriptId != null && ctx != ScriptContext.P2WSH)
				{
					if (repo.TryGetScript(witScriptId.HashForLookUp, out var nextScript))
					{
						var sub = InferFromScript(nextScript, repo, ScriptContext.P2WSH);
						return OutputDescriptor.NewWSH(sub);
					}
				}
				var witKeyId = PayToWitPubKeyHashTemplate.Instance.ExtractScriptPubKeyParameters(sc);
				if (witKeyId != null && ctx != ScriptContext.P2WSH)
				{
					if (repo.TryGetPubKey(witKeyId.AsKeyId(), out var pk))
						return OutputDescriptor.NewWPKH(InferPubKey(pk, repo, ctx));
				}
			}

			// Incase of unknown witness Output, we recover it to AddressDescriptor, 
			// Otherwise, RawDescriptor.
			if (template is PayToWitTemplate unknownWitnessTemplate)
			{
				var dest = unknownWitnessTemplate.ExtractScriptPubKeyParameters(sc);
				return OutputDescriptor.NewAddr(dest);
			}

			return OutputDescriptor.NewRaw(sc);
		}

		#endregion

		# region string (De)serializer

		public override string ToString()
		{
			var inner = ToStringHelper();
			return $"{inner}#{OutputDescriptor.GetCheckSum(inner)}";
		}

		public bool TryGetPrivateString(ISigningRepository secretProvider, out string result)
		{
			result = null;
			if (!TryGetPrivateStringHelper(secretProvider, out var inner))
				return false;
			result = $"{inner}#{OutputDescriptor.GetCheckSum(inner)}";
			return true;
		}

		private bool TryGetPrivateStringHelper(ISigningRepository secretProvider, out string result)
		{
			result = null;
			switch (this.Tag)
			{
				case Tags.AddressDescriptor:
				case Tags.RawDescriptor:
					result = this.ToStringHelper();
					return true;
				case Tags.PKDescriptor:
					if (!((PKDescriptor)this).PkProvider.TryGetPrivateString(secretProvider, out var privStr1))
						return false;
					result = $"pk({privStr1})";
					return true;
				case Tags.PKHDescriptor:
					if (!((PKHDescriptor)this).PkProvider.TryGetPrivateString(secretProvider, out var privStr2))
						return false;
					result = $"pkh({privStr2})";
					return true;
				case Tags.WPKHDescriptor:
					if (!((WPKHDescriptor)this).PkProvider.TryGetPrivateString(secretProvider, out var privStr3))
						return false;
					result = $"wpkh({privStr3})";
					return true;
				case Tags.ComboDescriptor:
					if (!((ComboDescriptor)this).PkProvider.TryGetPrivateString(secretProvider, out var privStr4))
						return false;
					result = $"combo({privStr4})";
					return true;
				case Tags.MultisigDescriptor:
					var subKeyList = new List<string>();
					var multi = (MultisigDescriptor)this;
					foreach (var prov in (multi.PkProviders))
					{
						if (!prov.TryGetPrivateString(secretProvider, out var tmp))
							return false;
						subKeyList.Add(tmp);
					}
					result = $"multi({multi.Threshold},{String.Join(",", subKeyList)})";
					return true;
				case Tags.SHDescriptor:
					if (!((SHDescriptor)this).Inner.TryGetPrivateStringHelper(secretProvider, out var shInner))
						return false;
					result = $"sh({shInner})";
					return true;
				case Tags.WSHDescriptor:
					if (!((WSHDescriptor)this).Inner.TryGetPrivateStringHelper(secretProvider, out var wshInner))
						return false;
					result = $"wsh({wshInner})";
					return true;
			}
			throw new Exception("Unreachable");
		}

		private string ToStringHelper()
		{
			switch (this)
			{
				case AddressDescriptor self:
					return $"addr({self.Address})";
				case RawDescriptor self:
					return $"raw({self.Script})";
				case PKDescriptor self:
					return $"pk({self.PkProvider})";
				case PKHDescriptor self:
					return $"pkh({self.PkProvider})";
				case WPKHDescriptor self:
					return $"wpkh({self.PkProvider})";
				case ComboDescriptor self:
					return $"combo({self.PkProvider})";
				case MultisigDescriptor self:
					var pksStr = String.Join(",", self.PkProviders);
					return $"multi({self.Threshold},{pksStr})";
				case SHDescriptor self:
					return $"sh({self.Inner.ToStringHelper()})";
				case WSHDescriptor self:
					return $"wsh({self.Inner.ToStringHelper()})";
			}
			throw new Exception("unreachable");
		}
		public static OutputDescriptor Parse(string desc, bool requireCheckSum = false, ISigningRepository repo = null)
			=> OutputDescriptorParser.ParseOD(desc, requireCheckSum, repo);

		public static bool TryParse(string desc, out OutputDescriptor result, bool requireCheckSum = false, ISigningRepository repo = null)
			=> OutputDescriptorParser.TryParseOD(desc, out result, requireCheckSum, repo);

		#endregion

		#region Equatable

		public sealed override bool Equals(object obj)
			=> Equals(obj as OutputDescriptor);

		public bool Equals(OutputDescriptor other)
		{
			if (other == null || this.Tag != other.Tag)
				return false;

			switch (this)
			{
				case AddressDescriptor self:
					return self.Address.Equals(((AddressDescriptor)other).Address);
				case RawDescriptor self:
					return self.Script.Equals(((RawDescriptor)other).Script);
				case PKDescriptor self:
					return self.PkProvider.Equals(((PKDescriptor)other).PkProvider);
				case PKHDescriptor self:
					return self.PkProvider.Equals(((PKHDescriptor)other).PkProvider);
				case WPKHDescriptor self:
					return self.PkProvider.Equals(((WPKHDescriptor)other).PkProvider);
				case ComboDescriptor self:
					return self.PkProvider.Equals(((ComboDescriptor)other).PkProvider);
				case MultisigDescriptor self:
					var otherM = (MultisigDescriptor)other;
					return self.Threshold == otherM.Threshold && self.PkProviders.SequenceEqual(otherM.PkProviders);
				case SHDescriptor self:
					return self.Inner.Equals(((SHDescriptor)other).Inner);
				case WSHDescriptor self:
					return self.Inner.Equals(((WSHDescriptor)other).Inner);
			}
			throw new Exception("Unreachable!");
		}

		public override int GetHashCode()
		{
			if (this != null)
			{
				int num = 0;
				switch (this)
				{
					case AddressDescriptor self:
						{
							num = 0;
							return -1640531527 + self.Address.GetHashCode() + ((num << 6) + (num >> 2));
						}
					case RawDescriptor self:
						{
							num = 1;
							return -1640531527 + self.Script.GetHashCode() + ((num << 6) + (num >> 2));
						}
					case PKDescriptor self:
						{
							num = 2;
							return -1640531527 + self.PkProvider.GetHashCode() + ((num << 6) + (num >> 2));
						}
					case PKHDescriptor self:
						{
							num = 3;
							return -1640531527 + self.PkProvider.GetHashCode() + ((num << 6) + (num >> 2));
						}
					case WPKHDescriptor self:
						{
							num = 4;
							return -1640531527 + self.PkProvider.GetHashCode() + ((num << 6) + (num >> 2));
						}
					case ComboDescriptor self:
						{
							num = 5;
							return -1640531527 + self.PkProvider.GetHashCode() + ((num << 6) + (num >> 2));
						}
					case MultisigDescriptor self:
						{
							num = 6;
							return -1640531527 + self.PkProviders.GetHashCode() + ((num << 6) + (num >> 2));
						}
					case SHDescriptor self:
						{
							num = 7;
							return -1640531527 + self.Inner.GetHashCode() + ((num << 6) + (num >> 2));
						}
					case WSHDescriptor self:
						{
							num = 8;
							return -1640531527 + self.Inner.GetHashCode() + ((num << 6) + (num >> 2));
						}
				}
			}
			return 0;
		}

		#endregion

		#region checksum
		/** The character set for the checksum itself (same as bech32). */
		static readonly char[] CHECKSUM_CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".ToCharArray();
		static readonly string INPUT_CHARSET_STRING =
		"0123456789()[],'/*abcdefgh@:$%{}" +
        "IJKLMNOPQRSTUVWXYZ&+-.;<=>?!^_|~" +
        "ijklmnopqrstuvwxyzABCDEFGH`#\"\\ ";

		static readonly char[] INPUT_CHARSET = INPUT_CHARSET_STRING.ToCharArray();

		internal static string GetCheckSum(string desc)
		{
			ulong c = 1;
			int cls = 0;
			int clscount = 0;
			foreach(var ch in desc.ToCharArray())
			{
				var pos = INPUT_CHARSET_STRING.IndexOf(ch);
				if (pos == -1)
					return "";
				c = PolyMod(c, pos & 31);
				cls = cls * 3 + (pos >> 5);
				if (++clscount == 3)
				{
					c = PolyMod(c, cls);
					cls = 0;
					clscount = 0;
				}
			}
			if (clscount > 0) c = PolyMod(c, cls);
			for (int j = 0; j < 8; ++j) c = PolyMod(c, 0);
			c ^= 1;
			var result = new char[8];
			for (int j = 0; j < 8; ++j)
			{
				result[j] = CHECKSUM_CHARSET[(c >> (5 * (7 - j))) & 31];
			}
			return new String(result);
		}
		static ulong PolyMod(ulong c, int val)
		{
			ulong c0 = c >> 35;
			c = ((c & 0x7ffffffffUL) << 5) ^ (ulong)val;
			if ((c0 & 1UL) != 0) c ^= 0xf5dee51989;
			if ((c0 & 2UL) != 0) c ^= 0xa9fdca3312;
			if ((c0 & 4UL) != 0) c ^= 0x1bab10e32d;
			if ((c0 & 8) != 0) c ^= 0x3706b1677a;
			if ((c0 & 16) != 0) c ^= 0x644d626ffd;
			return c;
		}

		#endregion
	}
}