////////////////////////////////////////////////////////////////////////////////////////////
// Copyright © 2020 xx network SEZC                                                       //
//                                                                                        //
// Use of this source code is governed by a license that can be found in the LICENSE file //
////////////////////////////////////////////////////////////////////////////////////////////

package wots

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"github.com/xx-labs/sleeve/hasher"
	"testing"
)

func TestDecodeParams(t *testing.T) {
	// Decode level0 params
	params := DecodeParams(Level0)

	if !params.Equal(level0Params) {
		t.Fatalf("DecodeParams() returned wrong params. Got %s, expected %s", params, level0Params)
	}

	// Decode level1 params
	params = DecodeParams(Level1)

	if !params.Equal(level1Params) {
		t.Fatalf("DecodeParams() returned wrong params. Got %s, expected %s", params, level1Params)
	}

	// Decode level2 params
	params = DecodeParams(Level2)

	if !params.Equal(level2Params) {
		t.Fatalf("DecodeParams() returned wrong params. Got %s, expected %s", params, level2Params)
	}

	// Decode level3 params
	params = DecodeParams(Level3)

	if !params.Equal(level3Params) {
		t.Fatalf("DecodeParams() returned wrong params. Got %s, expected %s", params, level3Params)
	}

	// Decode consensus params
	params = DecodeParams(Consensus)

	if !params.Equal(consensusParams) {
		t.Fatalf("DecodeParams() returned wrong params. Got %s, expected %s", params, consensusParams)
	}

	// Decode random params
	params = DecodeParams(ParamsEncodingLen)

	if params != nil {
		t.Fatalf("DecodeParams() should return nil for invalid params encoding")
	}
}

func TestEncodeParams(t *testing.T) {
	// Encode level0 params
	enc := EncodeParams(level0Params)

	if enc != Level0 {
		t.Fatalf("EncodeParams() returned wrong encoding. Got %d, expected %d", enc, Level0)
	}

	// Encode level1 params
	enc = EncodeParams(level1Params)

	if enc != Level1 {
		t.Fatalf("EncodeParams() returned wrong encoding. Got %d, expected %d", enc, Level1)
	}

	// Encode level2 params
	enc = EncodeParams(level2Params)

	if enc != Level2 {
		t.Fatalf("EncodeParams() returned wrong encoding. Got %d, expected %d", enc, Level2)
	}

	// Encode level3 params
	enc = EncodeParams(level3Params)

	if enc != Level3 {
		t.Fatalf("EncodeParams() returned wrong encoding. Got %d, expected %d", enc, Level3)
	}

	// Encode consensus params
	enc = EncodeParams(consensusParams)

	if enc != Consensus {
		t.Fatalf("EncodeParams() returned wrong encoding. Got %d, expected %d", enc, Consensus)
	}

	// Encode random params
	params := NewParams(24, 32, hasher.SHA2_256, hasher.BLAKE2B_256)
	enc = EncodeParams(params)

	if enc != ParamsEncodingLen {
		t.Fatalf("EncodeParams() returned wrong encoding. Got %d, expected %d", enc, ParamsEncodingLen)
	}
}

func TestDecodeTransactionSignature(t *testing.T) {
	key := NewKeyFromSeed(level0Params, getRandData(t, 32), getRandData(t, 32))

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	// Test decoding
	msg := getRandData(t, 256)

	sig := key.Sign(msg)
	pk := key.ComputePK()

	ret := make([]byte, 0, PKSize)
	ret, _ = DecodeTransactionSignature(ret, msg, sig)

	if !bytes.Equal(ret, pk) {
		t.Fatalf("Key.Sign + DecodeTransactionSignature are not consistent! Got: %x, expected: %x",
			ret, pk)
	}

	// Test wrong inputs
	ret = ret[:0]
	var err error
	ret, err = DecodeTransactionSignature(ret, nil, sig)

	if ret != nil || err == nil {
		t.Fatalf("DecodeTransactionSignature() should return error for invalid message argument")
	}

	ret, err = DecodeTransactionSignature(ret, msg, nil)

	if ret != nil || err == nil {
		t.Fatalf("DecodeTransactionSignature() should return error for invalid signature argument")
	}

	// Test attempting to decode a signature with consensus params
	key = NewKey(consensusParams, rand.Reader)

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	sig = key.Sign(msg)
	ret, err = DecodeTransactionSignature(ret, msg, sig)

	if ret != nil || err == nil {
		t.Fatalf("DecodeTransactionSignature() should return error if signature used consensus params")
	}

	// Test attempting to decode a signature with unknown params
	key = NewKey(NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256), rand.Reader)

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	sig = key.Sign(msg)
	ret, err = DecodeTransactionSignature(ret, msg, sig)

	if ret != nil || err == nil {
		t.Fatalf("DecodeTransactionSignature() should return error if signature used unkwown params")
	}
}

func TestVerify(t *testing.T) {
	// Test verify a consensus signature
	key := NewKeyFromSeed(level3Params, getRandData(t, 32), getRandData(t, 32))

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	msg := getRandData(t, 254)

	sig := key.Sign(msg)
	pk := key.ComputePK()
	t.Logf("%x", sig)
	t.Logf("%x", pk)
	t.Logf("%x", msg)

	valid, _ := Verify(msg, sig, pk)

	if !valid {
		t.Fatalf("Key.Sign + Verify are not consistent!")
	}

	// Test wrong inputs
	var err error
	_, err = Verify(nil, sig, pk)

	if err == nil {
		t.Fatalf("Verify() should return error for invalid message argument")
	}

	_, err = Verify(msg, nil, pk)

	if err == nil {
		t.Fatalf("Verify() should return error for invalid signature argument")
	}

	// Test attempting to verify a signature with unknown params
	key = NewKey(NewParams(32, 32, hasher.BLAKE3_256, hasher.BLAKE3_256), rand.Reader)

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	sig = key.Sign(msg)
	pk = key.ComputePK()
	_, err = Verify(msg, sig, pk)

	if err == nil {
		t.Fatalf("Verify() should return error if signature used unkwown params")
	}
}

func TestVerifyGenerate(t *testing.T) {
	// Test verify a consensus signature
	key := NewKeyFromSeed(consensusParams, getRandData(t, 32), getRandData(t, 32))

	if key == nil {
		t.Fatalf("NewKey returned nil")
	}

	key.Generate()

	msg := getRandData(t, 256)

	sig := key.Sign(msg)
	pk := key.ComputePK()

	valid, _ := Verify(msg, sig, pk)

	if !valid {
		t.Fatalf("Key.Sign + Verify are not consistent!")
	}
}

func mustDecodeHex(t *testing.T, str string) []byte {
	b, err := hex.DecodeString(str)
	if err != nil {
		t.Fatalf("failed to decode hex string: %s", err)
	}

	return b
}

func TestVerify_ConformanceTests(t *testing.T) {
	// these test vectors are generated from the Rust WOTS+ implementation.
	type testCase struct {
		signature string
		publicKey string
	}

	testCases := []testCase{
		{ // level 0 params
			signature: "00e976fa38cc8e928c243a9cb3bbf200e38e9a684c5bb79399025381b57f91ef0a0d0990f26b2a10ad4cbe5e4327551841f927642f73251ea743984e64e358232af7757306e956e016994e939308e55455a1ed38667076756c2c5016ec1cd36e03092e2c5cdb04f5c69c75414d86f8fb7731494f1e7ca2f6352d92d15b20c584eaa07c0d913f54f060bb3ccf7ce483f8c024fc950ca3eeebb74cb26cd5f613d0cda2de09c436b21561c126b40b3683969397ae5ec0bb70e1106b978532b40ff35c1f2a7887b4ff26b54a90604edd57eefd163564883670b0ee98d857e3066e604d1eac41abf1f0fa10f5fb8e7f8c70ccefc0a3db73beb93568968cdafdd21996c46f78612184dddaed536f113b84c7870432e4be929d8aa75dae118850da0add284d5a6a42a89209faadf33651b3ea6c8d4f3072ebb4697201295a327c7e9ee8532d557459ea6ce880856b71371df7ae225194f94c3dcc1e7db120e816ed970f24cee35ae3d80737961cfbc931c7560635b3962b1086d8c091916b3e11c8ceb434a9776939243148b5205af9ddfc1ceda4f5abbc9ece7dbedb5f4dd51d3c46a76b64916b50d1d922acb45262927884e9692c0f89fa575779ea303228f6d2c498ef49087ccb4c58796cb1dac8c36289b28e1e1da5a865256a7bc1b952ca4030179abe48680b7d09959bad84f25621f4e163409578907b292ed4572172b87718b2f6c88dbfbf86587b54cd1fe14f36581d1c27e7c518f83fd914183b5fc68d17b6ae9f8893ba310a7f53",
			publicKey: "94e53ffe4d8238994d471ab52ac6ad99529dba7846983baf5437985638567cd9",
		},
		{ // level 1 params
			signature: "0105c3534b623f91293b7117bffa814e2c214447d383e41b7e2be1e041fd4b4e87c7795864aabec7986bbd05f1dbe08bb395e586e7b1a6c4b32d6a906e6dfb09296fedfabe8028796c230cfa28ef5237094b4be7a47fd16ac350babcf121e97ba51c59375d401ede2242ae7618fc4b93bba2affa9ef286691b93bacde3f103498e6ef759c2e98d1a33f680c847d8145e6aef3cd4448408b38f54c0669b73cba79c203435ca0a471f034b8450b45e6b405556688cca0420b112bebf809137546b401173a4094251d9dfe7ab6f49bf9c6e1ecfcde5d6feda0954a03fd89e1b48926697f6d2ef513544353fac2884b4a0b0f1bed4674bffe6af71852d329e495f7b7ba776730a45967a8de7bea6ab04596ce4b2eede2a1e086858a7b46318e48819da6b1078eeb2ed3e252504a14b404fefe5018d1ba31989e2f84caa10e35800e12f8d94b9b8cf26f7424a9167f4459f33154da93833ac88fea2b0a3ecb83b8c36f00bfba92b349627d4072f7f4828cfbe38f1098c54954228912214c258f86fcc3f817814a27646eb6b8c6086d52dd14a29a8499d8b611389867920f2b224d66a071be4c6c1f0765b2fa51a6f256d4a2d1e05fed9a6e81f33676a6ab2187c33b3fb74ab8944b1b686e3fc5b284cbbbdd7b4ebce1a58f801ff808c22d3b294657920ffd2061080bd3ac7b290d4f8d831192f91d05a62274d4d4b4b72552d898bd4ce9d85f816ec528f5e28a256a5b58a3b0b4b5c6c507c152e43a4043d160b20de6029206419f0613d325f830b2650b9addbf1b8387f59e9b6cd85c61ed6bbafa78ec41d03ee4dd5957e4c3f85e533ca039a7a2c4248811c665b28c61137f427104468c4f0465ba15f34161d40379377b4787475c55a5a7ecc76479180e1d4643a6a36a502dd1fdb4193dba9646d072edbf2",
			publicKey: "5652ed4ba449dcb30b6ce7591294dd751655df2de25528619584496e0e03f140",
		},
		{ // level 2 params
			signature: "022a530558355ec4fe35f3347eb282a3a04809016404ffd3b35b1e50d8e969a004402974bf6589d9465146f75d7ad16c2ba124633dcc6a46943a7e68a5ce9a5ba36463d50ded15f0b9e0f54e01effee8b039671b14cb16bd584f6c7025107c4419c3f6184c8b319dae154605cc0697cc83f3dace3871b7e7abf70bb2c67b704bf4564c2c317600ccc1693cad281a39badaa77d69d8e2945feb07e15a0ffa36b5367a07a87968171a27fffd8e93ef872c9580683eec46beea38eb9ba4b4df0cf01098e3c5a1336d1c184a37b5cebc95498fbe717935b8c760a896b10bca3b1eb3b0caabcaa9127bd6413fa7b9692ef45a6f75e67be28de60b22ea29c53f5ff69b15e6f88a0ed613cf387ef4893b67309c4acb59dd4e0d9ea52edb48bda51ce7667846c3ebe3b26da41dad13504a0033bf07d54774806d6eecd4a0464b5df096d4c76720d30f3b152bd1dec4ccc16debae254cd5926b4f4f2a3c7821237f25eb14e0ad2afc8dd02f6227e40a8a48e5edc4ee4e62efa49b3c64698c55ec86e01a0249468801ccc102b12acb63647af97a6416edcd73dd7f5a64a36e5df20e46db8019d2943749e43dc48c9a46cb3a7f2d593ff4b44d76c2c48efec8b7b8d047da320f5031e760a97b4f8466c4b070631239b02d45dcecc0f3153cb252e793b0e3680435418d5d458636456fd16b50fc6fc874a6dbf711ef2cea66224e5979a7eadd8c734c88859101d6d43dc210b300fa5626538dd21f56887a3389e242b35cddc85527f4aea61222fcf596bb31f849fdac80c934767f7c4044edb5f66b4707cf334a44a0652b6ca349c3e9fab87b427193adfc4afa02e7f951604768093f9a0e172fc1fcc5f3f698156dee4a1541a71cc974d42743e0cfa30f810eac9b7983dfb53ba1158a1a205d05829b4e610967c420ecd57fed48c8d4b27781db91da873427c610d7e1dda657e326a30a4dca23a99dd4b5bb8e8754b9a85b0cccf47a64c365af94fa46341e38b30fdc3b7f6615e10f4c66f04379be078946b7b7a04ca264feba696db5dbff5cf35a78d9af605a38e2213359df13e09a1745",
			publicKey: "d7d4ffe2beb5da7f8e849fd512f11aa27472d55ea4c26170099eae5850181ebc",
		},
		{ // level 3 params
			signature: "03a9ed16737780f7e0a60cce73d17f6c71b37f029451513e617a8ee7f1f58331e57195c5a980074d516f790e4c3f381e05f2510f6c7e3bd496dc5de56f4eca69e39542752914a8305439e8935dae4202bee5aa14d52e0cf390ef03c8dd578004a10eeb4168ccee7029c4cde53a50feb93adbaf1adf425aabd7d1e8e4212bf88d721dec1b5cdb05129c198505c09734ce45487655dc978c67c2bf73f37923998ca3af494437931b997c949b77226d20f019da0f45c43da6ad93894314bf6b22aae559bb26563990c56ae2d2405425d82a253f86eef8a72763e5952c0a0454353634a1a7176bfcf87419470018dce7e17b45f6ac110b933e3fffcc4299f1e1018d28f3b1ec760cfa8b87c529aff874a4be25883e77319b305aa44860ee8c2c64e56f8a6b9cb5e20c34df07b6cf82bee375987016166b5f58817bdf3e7ee9278dd176d83ad8099d40fc32bf97f0dfaed5a17207dc58f554d512ca34c19066d390c987de582a921de51b9197e62de4f6f3c15a83c60a98dae4af75ced1bcbd4e7dcd1ed97747a9d5fda193a8e2b8c73880624a78ba55e0302a16af5560c0f85f00130f642a334e33c214d512a0bb041ed25e3b566ffe3ff3dc6c7513f7fbe2a5ce79dce5afa68a8cec5e8645a20671957046130a172eedf359df978014ad9fc668e5d7603c2aecc7604af4b1a5b7c0ae4c29218092422399a035a8df9c160fb39facf123a163366e761721c9f166f50e5275bb004a764f95a5ce4aeb565d88613785c9e22352c7a394a4e5d8e32b22d6fd514c5460e8130d0bc60b1640e5f3dcebb834d89fa07cbb5ca0411316b45b19317501f76e8fbf2144dc5be57d93ed8e9504a9b822913ebf2224ce9120f51bafa930f8488e1afe9053723098a598d4d0cec9c665d467ae6dfc2fc6b2c69aed6200cf4720704dd2dc539fa63444de96ff4134b2ad2cf4a505ad58ea3059534b7740a86211623d835e44e19dbc9a4cfefe9bcb2427b190c48d8a2c4feb0daef101a10e503b060d96135a4f4d3fb4acdb19c235d4e7e0210ebcf98600aafb8d31d2976ed382cea200197920ec39255b7fe73a98d0460feab41f2308707c164c0784e9f79a5c47b0dd9f5bbdbb5b45c5bd6e1f6724a2fe6a3bc96c322520b429f52eef3ac23064ebd1700c6fe776f6c914da6071b7dc92b329b159be619bbb6e5eae850208ee451821c169dfc6c29ffe4b4adf78d8",
			publicKey: "cb1b29543555095b82c98b02690a598f70a799b3e1b484570e0aa87a20578cec",
		},
		{ // consensus params
			signature: "04634bc8328ad63741c58e45fd386acf0264e1ee8d9df93bb0c927df8aeab9c4b418d8025ad80b7cd6d1070652342ddb42d15b717f44675aa67983b0efecde49ee8b2df6ee94d846a3351d923f9fe4063f5f07aca95bacedc93b65efdd8c0c146117818545898788e70e5f3df4fc3080e946593ca6bbd3f0ccb5c396a27ea674554bda02419b7d0abbd7940e8489f9e0ebd733d4e5152cb0d2a91ffa73b6f63dc0f4065b4620edfecda91cbbd7a5b226436f58de506459bd755c00786c6e479d7e0da6169716073c299652a886ae443d67e794c4d5bd172750a10c083b617db0e3f896578773a4d9e0739054c5c3162bb5779ab443916480251a3e7bc33cae913aae579018eb44b2c6ff605d5f81ca6136425eee42dd9b229cc5e46d764831c5b7838eafad8811e2104729b7e4a4594db24c5d18e9c5a05959c257a6e3aee2ecd0c9c4f0da1b4188901df1c41a815fef9910f54172caef28acbaf169bdd0c78bbf813af69cf5a1af4cc083ed72fcf3cd04c3715fcb0b68fd62d1389c5251699fcf5a2a6448c20837d583c2c5cc043911ef0e6a586f83171886ffc5e2cd7f6826e596a3d91d9725479dd4636c2c76a8844a689c43a38b2b0fa1d6ae371ff1c32a6324f132b05e23bb5fdaa83da233e646c259f9afe156c9c812f5cbca387f1f872e9fa472408e7b5a0bd7ce87376c8b247e6ab3edb84aa7f4e48af92baa558cb1d8090663d70414f8049fc2016ce216e77d665acd442a8ec8c046abf0b532ecd68a5f7e127e39f2acf31fd0c8a6a3cd1e55ae8f2a15f9ecfc42bb517ad6dbffb49b67bac14e3f9565a1366f40a72f376b4b55d47778202b586dcbf574e147c371fa1b76ad8ec11024452aab2c17affb17bb9e6b698717427991d4c5575e1eae15739a29b16edde684e0a35a099063e5389040f51ed36470ca8f2a63288fe5a11253e2fbdbe8fe17de006042ee000e126dd18110530e2f7fd32baf4ebdf1a65d96f3db4dc4a5f313f76e3a96be7818f209287674120a737e00bcf44fd48085120b3190e8371dfee2158215bed5904ef45d923a6b95bc80180e520c980cf2122fbd14b0080a7fa750897e70c7a3a07c95020bf83042603071e4ff96ede179cca43fa19c9f7964aa6c9767bce35e74eda75b23d8aec85880f1615ce1e2af24f61be3c0e98f09110a12ec13cd785906ffd16e8d069261aa5c57847859cb375145a88f0926b96110feb1a69dfcbe3ca4aaa3c712e41bcec59d21fd4192c456e914a45a75399fbd6c4bf926bf6d2b36c69734f58651e39491ce84c390b4a4e14d7ae360d02a2e14eca41037d7ef478a3f92bf4235476c076176855c7ca1066242643e50d8c6294c4e9a7e158c969dde4b094c7693420eb618850f7c4d972ee9aa1284c7ce9d4b2dc8b332578337473a4bc934af2a821aa7815b10be401fc741e540ab194b4c2053623cf1ae1b0483a0c755ff90480de4729077dd1b26628d109d0067d033113f9eec9bac1993c94b37e7f9f4fadb23102ef7356734a1b95d2f67117ae807fd72aea45347845dab0ed8e805bc910d16773b09afa6b9bf355219cb3349a3d8",
			publicKey: "d172d6c9e3c079c1caa88123b763eebe8381bd2cc5e6bf9e166fa9b1a75a7e45",
		},
	}

	message := mustDecodeHex(t, "6363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363636363")

	for i, tc := range testCases {
		ok, _ := Verify(message, mustDecodeHex(t, tc.signature), mustDecodeHex(t, tc.publicKey))
		if !ok {
			t.Fatalf("Failed to verify signature generated by Rust: idx=%d", i)
		}
	}
}
