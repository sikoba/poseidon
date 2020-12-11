require "spec"
require "openssl"
require "../src/poseidon.cr"

def gen_test_strings(max = 50)
  r = Random.new
  # arrays of size 5-50
  test_data = Array(String).new
  n = r.rand(5..max)
  (0..n).each do |i|
    s = r.rand(5..500)
    b = r.random_bytes(s)
    test_data.push(String.new(b).scrub('o').dump_unquoted);
  end
  return test_data
end

def gen_test_arrays(max = 50, exact = 0)
  r = Random.new
  # arrays of size 5-50
  test_data = Array(Array(UInt8)).new
  n = r.rand(5..max)
  if (exact > 0)
    n = exact
  end
  (0..n).each do |i|
    s = 62# r.rand(5..500)
    b = r.random_bytes(s)
    test_data.push(b.to_a);
  end
  return test_data
end


describe "Poseidon hash" do
  it "Check perm of [0,1,2]" do
    r_p = 57;
    r_f = 8;
    t = 3;
    prime = BigInt.new("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",16);
    input_words = Array(BigInt).new();
    (0...t).each  do |i|
        input_words.push(BigInt.new(i));
    end
    triton =  Poseidon.new(prime, 128 , 0);
    trident = PoseidonParams.new();
    trident.set_params(prime, 5, r_f, r_p, t)
    trident.init_generator(); 
    rc = [BigInt.new("0ee9a592ba9a9518d05986d656f40c2114c4993c11bb29938d21d47304cd8e6e",16), BigInt.new("00f1445235f2148c5986587169fc1bcd887b08d4d00868df5696fff40956e864",16), BigInt.new("08dff3487e8ac99e1f29a058d0fa80b930c728730b7ab36ce879f3890ecf73f5",16), BigInt.new("2f27be690fdaee46c3ce28f7532b13c856c35342c84bda6e20966310fadc01d0",16), BigInt.new("2b2ae1acf68b7b8d2416bebf3d4f6234b763fe04b8043ee48b8327bebca16cf2",16), BigInt.new("0319d062072bef7ecca5eac06f97d4d55952c175ab6b03eae64b44c7dbf11cfa",16), BigInt.new("28813dcaebaeaa828a376df87af4a63bc8b7bf27ad49c6298ef7b387bf28526d",16), BigInt.new("2727673b2ccbc903f181bf38e1c1d40d2033865200c352bc150928adddf9cb78",16), BigInt.new("234ec45ca27727c2e74abd2b2a1494cd6efbd43e340587d6b8fb9e31e65cc632",16), BigInt.new("15b52534031ae18f7f862cb2cf7cf760ab10a8150a337b1ccd99ff6e8797d428",16), BigInt.new("0dc8fad6d9e4b35f5ed9a3d186b79ce38e0e8a8d1b58b132d701d4eecf68d1f6",16), BigInt.new("1bcd95ffc211fbca600f705fad3fb567ea4eb378f62e1fec97805518a47e4d9c",16), BigInt.new("10520b0ab721cadfe9eff81b016fc34dc76da36c2578937817cb978d069de559",16), BigInt.new("1f6d48149b8e7f7d9b257d8ed5fbbaf42932498075fed0ace88a9eb81f5627f6",16), BigInt.new("1d9655f652309014d29e00ef35a2089bfff8dc1c816f0dc9ca34bdb5460c8705",16), BigInt.new("04df5a56ff95bcafb051f7b1cd43a99ba731ff67e47032058fe3d4185697cc7d",16), BigInt.new("0672d995f8fff640151b3d290cedaf148690a10a8c8424a7f6ec282b6e4be828",16), BigInt.new("099952b414884454b21200d7ffafdd5f0c9a9dcc06f2708e9fc1d8209b5c75b9",16), BigInt.new("052cba2255dfd00c7c483143ba8d469448e43586a9b4cd9183fd0e843a6b9fa6",16), BigInt.new("0b8badee690adb8eb0bd74712b7999af82de55707251ad7716077cb93c464ddc",16), BigInt.new("119b1590f13307af5a1ee651020c07c749c15d60683a8050b963d0a8e4b2bdd1",16), BigInt.new("03150b7cd6d5d17b2529d36be0f67b832c4acfc884ef4ee5ce15be0bfb4a8d09",16), BigInt.new("2cc6182c5e14546e3cf1951f173912355374efb83d80898abe69cb317c9ea565",16), BigInt.new("005032551e6378c450cfe129a404b3764218cadedac14e2b92d2cd73111bf0f9",16), BigInt.new("233237e3289baa34bb147e972ebcb9516469c399fcc069fb88f9da2cc28276b5",16), BigInt.new("05c8f4f4ebd4a6e3c980d31674bfbe6323037f21b34ae5a4e80c2d4c24d60280",16), BigInt.new("0a7b1db13042d396ba05d818a319f25252bcf35ef3aeed91ee1f09b2590fc65b",16), BigInt.new("2a73b71f9b210cf5b14296572c9d32dbf156e2b086ff47dc5df542365a404ec0",16), BigInt.new("1ac9b0417abcc9a1935107e9ffc91dc3ec18f2c4dbe7f22976a760bb5c50c460",16), BigInt.new("12c0339ae08374823fabb076707ef479269f3e4d6cb104349015ee046dc93fc0",16), BigInt.new("0b7475b102a165ad7f5b18db4e1e704f52900aa3253baac68246682e56e9a28e",16), BigInt.new("037c2849e191ca3edb1c5e49f6e8b8917c843e379366f2ea32ab3aa88d7f8448",16), BigInt.new("05a6811f8556f014e92674661e217e9bd5206c5c93a07dc145fdb176a716346f",16), BigInt.new("29a795e7d98028946e947b75d54e9f044076e87a7b2883b47b675ef5f38bd66e",16), BigInt.new("20439a0c84b322eb45a3857afc18f5826e8c7382c8a1585c507be199981fd22f",16), BigInt.new("2e0ba8d94d9ecf4a94ec2050c7371ff1bb50f27799a84b6d4a2a6f2a0982c887",16), BigInt.new("143fd115ce08fb27ca38eb7cce822b4517822cd2109048d2e6d0ddcca17d71c8",16), BigInt.new("0c64cbecb1c734b857968dbbdcf813cdf8611659323dbcbfc84323623be9caf1",16), BigInt.new("028a305847c683f646fca925c163ff5ae74f348d62c2b670f1426cef9403da53",16), BigInt.new("2e4ef510ff0b6fda5fa940ab4c4380f26a6bcb64d89427b824d6755b5db9e30c",16), BigInt.new("0081c95bc43384e663d79270c956ce3b8925b4f6d033b078b96384f50579400e",16), BigInt.new("2ed5f0c91cbd9749187e2fade687e05ee2491b349c039a0bba8a9f4023a0bb38",16), BigInt.new("30509991f88da3504bbf374ed5aae2f03448a22c76234c8c990f01f33a735206",16), BigInt.new("1c3f20fd55409a53221b7c4d49a356b9f0a1119fb2067b41a7529094424ec6ad",16), BigInt.new("10b4e7f3ab5df003049514459b6e18eec46bb2213e8e131e170887b47ddcb96c",16), BigInt.new("2a1982979c3ff7f43ddd543d891c2abddd80f804c077d775039aa3502e43adef",16), BigInt.new("1c74ee64f15e1db6feddbead56d6d55dba431ebc396c9af95cad0f1315bd5c91",16), BigInt.new("07533ec850ba7f98eab9303cace01b4b9e4f2e8b82708cfa9c2fe45a0ae146a0",16), BigInt.new("21576b438e500449a151e4eeaf17b154285c68f42d42c1808a11abf3764c0750",16), BigInt.new("2f17c0559b8fe79608ad5ca193d62f10bce8384c815f0906743d6930836d4a9e",16), BigInt.new("2d477e3862d07708a79e8aae946170bc9775a4201318474ae665b0b1b7e2730e",16), BigInt.new("162f5243967064c390e095577984f291afba2266c38f5abcd89be0f5b2747eab",16), BigInt.new("2b4cb233ede9ba48264ecd2c8ae50d1ad7a8596a87f29f8a7777a70092393311",16), BigInt.new("2c8fbcb2dd8573dc1dbaf8f4622854776db2eece6d85c4cf4254e7c35e03b07a",16), BigInt.new("1d6f347725e4816af2ff453f0cd56b199e1b61e9f601e9ade5e88db870949da9",16), BigInt.new("204b0c397f4ebe71ebc2d8b3df5b913df9e6ac02b68d31324cd49af5c4565529",16), BigInt.new("0c4cb9dc3c4fd8174f1149b3c63c3c2f9ecb827cd7dc25534ff8fb75bc79c502",16), BigInt.new("174ad61a1448c899a25416474f4930301e5c49475279e0639a616ddc45bc7b54",16), BigInt.new("1a96177bcf4d8d89f759df4ec2f3cde2eaaa28c177cc0fa13a9816d49a38d2ef",16), BigInt.new("066d04b24331d71cd0ef8054bc60c4ff05202c126a233c1a8242ace360b8a30a",16), BigInt.new("2a4c4fc6ec0b0cf52195782871c6dd3b381cc65f72e02ad527037a62aa1bd804",16), BigInt.new("13ab2d136ccf37d447e9f2e14a7cedc95e727f8446f6d9d7e55afc01219fd649",16), BigInt.new("1121552fca26061619d24d843dc82769c1b04fcec26f55194c2e3e869acc6a9a",16), BigInt.new("00ef653322b13d6c889bc81715c37d77a6cd267d595c4a8909a5546c7c97cff1",16), BigInt.new("0e25483e45a665208b261d8ba74051e6400c776d652595d9845aca35d8a397d3",16), BigInt.new("29f536dcb9dd7682245264659e15d88e395ac3d4dde92d8c46448db979eeba89",16), BigInt.new("2a56ef9f2c53febadfda33575dbdbd885a124e2780bbea170e456baace0fa5be",16), BigInt.new("1c8361c78eb5cf5decfb7a2d17b5c409f2ae2999a46762e8ee416240a8cb9af1",16), BigInt.new("151aff5f38b20a0fc0473089aaf0206b83e8e68a764507bfd3d0ab4be74319c5",16), BigInt.new("04c6187e41ed881dc1b239c88f7f9d43a9f52fc8c8b6cdd1e76e47615b51f100",16), BigInt.new("13b37bd80f4d27fb10d84331f6fb6d534b81c61ed15776449e801b7ddc9c2967",16), BigInt.new("01a5c536273c2d9df578bfbd32c17b7a2ce3664c2a52032c9321ceb1c4e8a8e4",16), BigInt.new("2ab3561834ca73835ad05f5d7acb950b4a9a2c666b9726da832239065b7c3b02",16), BigInt.new("1d4d8ec291e720db200fe6d686c0d613acaf6af4e95d3bf69f7ed516a597b646",16), BigInt.new("041294d2cc484d228f5784fe7919fd2bb925351240a04b711514c9c80b65af1d",16), BigInt.new("154ac98e01708c611c4fa715991f004898f57939d126e392042971dd90e81fc6",16), BigInt.new("0b339d8acca7d4f83eedd84093aef51050b3684c88f8b0b04524563bc6ea4da4",16), BigInt.new("0955e49e6610c94254a4f84cfbab344598f0e71eaff4a7dd81ed95b50839c82e",16), BigInt.new("06746a6156eba54426b9e22206f15abca9a6f41e6f535c6f3525401ea0654626",16), BigInt.new("0f18f5a0ecd1423c496f3820c549c27838e5790e2bd0a196ac917c7ff32077fb",16), BigInt.new("04f6eeca1751f7308ac59eff5beb261e4bb563583ede7bc92a738223d6f76e13",16), BigInt.new("2b56973364c4c4f5c1a3ec4da3cdce038811eb116fb3e45bc1768d26fc0b3758",16), BigInt.new("123769dd49d5b054dcd76b89804b1bcb8e1392b385716a5d83feb65d437f29ef",16), BigInt.new("2147b424fc48c80a88ee52b91169aacea989f6446471150994257b2fb01c63e9",16), BigInt.new("0fdc1f58548b85701a6c5505ea332a29647e6f34ad4243c2ea54ad897cebe54d",16), BigInt.new("12373a8251fea004df68abcf0f7786d4bceff28c5dbbe0c3944f685cc0a0b1f2",16), BigInt.new("21e4f4ea5f35f85bad7ea52ff742c9e8a642756b6af44203dd8a1f35c1a90035",16), BigInt.new("16243916d69d2ca3dfb4722224d4c462b57366492f45e90d8a81934f1bc3b147",16), BigInt.new("1efbe46dd7a578b4f66f9adbc88b4378abc21566e1a0453ca13a4159cac04ac2",16), BigInt.new("07ea5e8537cf5dd08886020e23a7f387d468d5525be66f853b672cc96a88969a",16), BigInt.new("05a8c4f9968b8aa3b7b478a30f9a5b63650f19a75e7ce11ca9fe16c0b76c00bc",16), BigInt.new("20f057712cc21654fbfe59bd345e8dac3f7818c701b9c7882d9d57b72a32e83f",16), BigInt.new("04a12ededa9dfd689672f8c67fee31636dcd8e88d01d49019bd90b33eb33db69",16), BigInt.new("27e88d8c15f37dcee44f1e5425a51decbd136ce5091a6767e49ec9544ccd101a",16), BigInt.new("2feed17b84285ed9b8a5c8c5e95a41f66e096619a7703223176c41ee433de4d1",16), BigInt.new("1ed7cc76edf45c7c404241420f729cf394e5942911312a0d6972b8bd53aff2b8",16), BigInt.new("15742e99b9bfa323157ff8c586f5660eac6783476144cdcadf2874be45466b1a",16), BigInt.new("1aac285387f65e82c895fc6887ddf40577107454c6ec0317284f033f27d0c785",16), BigInt.new("25851c3c845d4790f9ddadbdb6057357832e2e7a49775f71ec75a96554d67c77",16), BigInt.new("15a5821565cc2ec2ce78457db197edf353b7ebba2c5523370ddccc3d9f146a67",16), BigInt.new("2411d57a4813b9980efa7e31a1db5966dcf64f36044277502f15485f28c71727",16), BigInt.new("002e6f8d6520cd4713e335b8c0b6d2e647e9a98e12f4cd2558828b5ef6cb4c9b",16), BigInt.new("2ff7bc8f4380cde997da00b616b0fcd1af8f0e91e2fe1ed7398834609e0315d2",16), BigInt.new("00b9831b948525595ee02724471bcd182e9521f6b7bb68f1e93be4febb0d3cbe",16), BigInt.new("0a2f53768b8ebf6a86913b0e57c04e011ca408648a4743a87d77adbf0c9c3512",16), BigInt.new("00248156142fd0373a479f91ff239e960f599ff7e94be69b7f2a290305e1198d",16), BigInt.new("171d5620b87bfb1328cf8c02ab3f0c9a397196aa6a542c2350eb512a2b2bcda9",16), BigInt.new("170a4f55536f7dc970087c7c10d6fad760c952172dd54dd99d1045e4ec34a808",16), BigInt.new("29aba33f799fe66c2ef3134aea04336ecc37e38c1cd211ba482eca17e2dbfae1",16), BigInt.new("1e9bc179a4fdd758fdd1bb1945088d47e70d114a03f6a0e8b5ba650369e64973",16), BigInt.new("1dd269799b660fad58f7f4892dfb0b5afeaad869a9c4b44f9c9e1c43bdaf8f09",16), BigInt.new("22cdbc8b70117ad1401181d02e15459e7ccd426fe869c7c95d1dd2cb0f24af38",16), BigInt.new("0ef042e454771c533a9f57a55c503fcefd3150f52ed94a7cd5ba93b9c7dacefd",16), BigInt.new("11609e06ad6c8fe2f287f3036037e8851318e8b08a0359a03b304ffca62e8284",16), BigInt.new("1166d9e554616dba9e753eea427c17b7fecd58c076dfe42708b08f5b783aa9af",16), BigInt.new("2de52989431a859593413026354413db177fbf4cd2ac0b56f855a888357ee466",16), BigInt.new("3006eb4ffc7a85819a6da492f3a8ac1df51aee5b17b8e89d74bf01cf5f71e9ad",16), BigInt.new("2af41fbb61ba8a80fdcf6fff9e3f6f422993fe8f0a4639f962344c8225145086",16), BigInt.new("119e684de476155fe5a6b41a8ebc85db8718ab27889e85e781b214bace4827c3",16), BigInt.new("1835b786e2e8925e188bea59ae363537b51248c23828f047cff784b97b3fd800",16), BigInt.new("28201a34c594dfa34d794996c6433a20d152bac2a7905c926c40e285ab32eeb6",16), BigInt.new("083efd7a27d1751094e80fefaf78b000864c82eb571187724a761f88c22cc4e7",16), BigInt.new("0b6f88a3577199526158e61ceea27be811c16df7774dd8519e079564f61fd13b",16), BigInt.new("0ec868e6d15e51d9644f66e1d6471a94589511ca00d29e1014390e6ee4254f5b",16), BigInt.new("2af33e3f866771271ac0c9b3ed2e1142ecd3e74b939cd40d00d937ab84c98591",16), BigInt.new("0b520211f904b5e7d09b5d961c6ace7734568c547dd6858b364ce5e47951f178",16), BigInt.new("0b2d722d0919a1aad8db58f10062a92ea0c56ac4270e822cca228620188a1d40",16), BigInt.new("1f790d4d7f8cf094d980ceb37c2453e957b54a9991ca38bbe0061d1ed6e562d4",16), BigInt.new("0171eb95dfbf7d1eaea97cd385f780150885c16235a2a6a8da92ceb01e504233",16), BigInt.new("0c2d0e3b5fd57549329bf6885da66b9b790b40defd2c8650762305381b168873",16), BigInt.new("1162fb28689c27154e5a8228b4e72b377cbcafa589e283c35d3803054407a18d",16), BigInt.new("2f1459b65dee441b64ad386a91e8310f282c5a92a89e19921623ef8249711bc0",16), BigInt.new("1e6ff3216b688c3d996d74367d5cd4c1bc489d46754eb712c243f70d1b53cfbb",16), BigInt.new("01ca8be73832b8d0681487d27d157802d741a6f36cdc2a0576881f9326478875",16), BigInt.new("1f7735706ffe9fc586f976d5bdf223dc680286080b10cea00b9b5de315f9650e",16), BigInt.new("2522b60f4ea3307640a0c2dce041fba921ac10a3d5f096ef4745ca838285f019",16), BigInt.new("23f0bee001b1029d5255075ddc957f833418cad4f52b6c3f8ce16c235572575b",16), BigInt.new("2bc1ae8b8ddbb81fcaac2d44555ed5685d142633e9df905f66d9401093082d59",16), BigInt.new("0f9406b8296564a37304507b8dba3ed162371273a07b1fc98011fcd6ad72205f",16), BigInt.new("2360a8eb0cc7defa67b72998de90714e17e75b174a52ee4acb126c8cd995f0a8",16), BigInt.new("15871a5cddead976804c803cbaef255eb4815a5e96df8b006dcbbc2767f88948",16), BigInt.new("193a56766998ee9e0a8652dd2f3b1da0362f4f54f72379544f957ccdeefb420f",16), BigInt.new("2a394a43934f86982f9be56ff4fab1703b2e63c8ad334834e4309805e777ae0f",16), BigInt.new("1859954cfeb8695f3e8b635dcb345192892cd11223443ba7b4166e8876c0d142",16), BigInt.new("04e1181763050e58013444dbcb99f1902b11bc25d90bbdca408d3819f4fed32b",16), BigInt.new("0fdb253dee83869d40c335ea64de8c5bb10eb82db08b5e8b1f5e5552bfd05f23",16), BigInt.new("058cbe8a9a5027bdaa4efb623adead6275f08686f1c08984a9d7c5bae9b4f1c0",16), BigInt.new("1382edce9971e186497eadb1aeb1f52b23b4b83bef023ab0d15228b4cceca59a",16), BigInt.new("03464990f045c6ee0819ca51fd11b0be7f61b8eb99f14b77e1e6634601d9e8b5",16), BigInt.new("23f7bfc8720dc296fff33b41f98ff83c6fcab4605db2eb5aaa5bc137aeb70a58",16), BigInt.new("0a59a158e3eec2117e6e94e7f0e9decf18c3ffd5e1531a9219636158bbaf62f2",16), BigInt.new("06ec54c80381c052b58bf23b312ffd3ce2c4eba065420af8f4c23ed0075fd07b",16), BigInt.new("118872dc832e0eb5476b56648e867ec8b09340f7a7bcb1b4962f0ff9ed1f9d01",16), BigInt.new("13d69fa127d834165ad5c7cba7ad59ed52e0b0f0e42d7fea95e1906b520921b1",16), BigInt.new("169a177f63ea681270b1c6877a73d21bde143942fb71dc55fd8a49f19f10c77b",16), BigInt.new("04ef51591c6ead97ef42f287adce40d93abeb032b922f66ffb7e9a5a7450544d",16), BigInt.new("256e175a1dc079390ecd7ca703fb2e3b19ec61805d4f03ced5f45ee6dd0f69ec",16), BigInt.new("30102d28636abd5fe5f2af412ff6004f75cc360d3205dd2da002813d3e2ceeb2",16), BigInt.new("10998e42dfcd3bbf1c0714bc73eb1bf40443a3fa99bef4a31fd31be182fcc792",16), BigInt.new("193edd8e9fcf3d7625fa7d24b598a1d89f3362eaf4d582efecad76f879e36860",16), BigInt.new("18168afd34f2d915d0368ce80b7b3347d1c7a561ce611425f2664d7aa51f0b5d",16), BigInt.new("29383c01ebd3b6ab0c017656ebe658b6a328ec77bc33626e29e2e95b33ea6111",16), BigInt.new("10646d2f2603de39a1f4ae5e7771a64a702db6e86fb76ab600bf573f9010c711",16), BigInt.new("0beb5e07d1b27145f575f1395a55bf132f90c25b40da7b3864d0242dcb1117fb",16), BigInt.new("16d685252078c133dc0d3ecad62b5c8830f95bb2e54b59abdffbf018d96fa336",16), BigInt.new("0a6abd1d833938f33c74154e0404b4b40a555bbbec21ddfafd672dd62047f01a",16), BigInt.new("1a679f5d36eb7b5c8ea12a4c2dedc8feb12dffeec450317270a6f19b34cf1860",16), BigInt.new("0980fb233bd456c23974d50e0ebfde4726a423eada4e8f6ffbc7592e3f1b93d6",16), BigInt.new("161b42232e61b84cbf1810af93a38fc0cece3d5628c9282003ebacb5c312c72b",16), BigInt.new("0ada10a90c7f0520950f7d47a60d5e6a493f09787f1564e5d09203db47de1a0b",16), BigInt.new("1a730d372310ba82320345a29ac4238ed3f07a8a2b4e121bb50ddb9af407f451",16), BigInt.new("2c8120f268ef054f817064c369dda7ea908377feaba5c4dffbda10ef58e8c556",16), BigInt.new("1c7c8824f758753fa57c00789c684217b930e95313bcb73e6e7b8649a4968f70",16), BigInt.new("2cd9ed31f5f8691c8e39e4077a74faa0f400ad8b491eb3f7b47b27fa3fd1cf77",16), BigInt.new("23ff4f9d46813457cf60d92f57618399a5e022ac321ca550854ae23918a22eea",16), BigInt.new("09945a5d147a4f66ceece6405dddd9d0af5a2c5103529407dff1ea58f180426d",16), BigInt.new("188d9c528025d4c2b67660c6b771b90f7c7da6eaa29d3f268a6dd223ec6fc630",16), BigInt.new("3050e37996596b7f81f68311431d8734dba7d926d3633595e0c0d8ddf4f0f47f",16), BigInt.new("15af1169396830a91600ca8102c35c426ceae5461e3f95d89d829518d30afd78",16), BigInt.new("1da6d09885432ea9a06d9f37f873d985dae933e351466b2904284da3320d8acc",16), BigInt.new("2796ea90d269af29f5f8acf33921124e4e4fad3dbe658945e546ee411ddaa9cb",16), BigInt.new("202d7dd1da0f6b4b0325c8b3307742f01e15612ec8e9304a7cb0319e01d32d60",16), BigInt.new("096d6790d05bb759156a952ba263d672a2d7f9c788f4c831a29dace4c0f8be5f",16), BigInt.new("054efa1f65b0fce283808965275d877b438da23ce5b13e1963798cb1447d25a4",16), BigInt.new("1b162f83d917e93edb3308c29802deb9d8aa690113b2e14864ccf6e18e4165f1",16), BigInt.new("21e5241e12564dd6fd9f1cdd2a0de39eedfefc1466cc568ec5ceb745a0506edc",16), BigInt.new("1cfb5662e8cf5ac9226a80ee17b36abecb73ab5f87e161927b4349e10e4bdf08",16), BigInt.new("0f21177e302a771bbae6d8d1ecb373b62c99af346220ac0129c53f666eb24100",16), BigInt.new("1671522374606992affb0dd7f71b12bec4236aede6290546bcef7e1f515c2320",16), BigInt.new("0fa3ec5b9488259c2eb4cf24501bfad9be2ec9e42c5cc8ccd419d2a692cad870",16), BigInt.new("193c0e04e0bd298357cb266c1506080ed36edce85c648cc085e8c57b1ab54bba",16), BigInt.new("102adf8ef74735a27e9128306dcbc3c99f6f7291cd406578ce14ea2adaba68f8",16), BigInt.new("0fe0af7858e49859e2a54d6f1ad945b1316aa24bfbdd23ae40a6d0cb70c3eab1",16), BigInt.new("216f6717bbc7dedb08536a2220843f4e2da5f1daa9ebdefde8a5ea7344798d22",16), BigInt.new("1da55cc900f0d21f4a3e694391918a1b3c23b2ac773c6b3ef88e2e4228325161",16)];
    trident.round_constants.should eq rc
    output_words = triton.perm(input_words, trident)

    output_words[0].should eq BigInt.new("21b76cff5dbcfa38c432853dff5e00e686f868d04ce2fa8f91c87b0eb7cfd1c4",16);
    output_words[1].should eq BigInt.new("2d042d4fa0c5e0b133317306629ce7b9e5c41b1d5a33845999390c937f600d0f",16);
    output_words[2].should eq BigInt.new("2142656843ccc057488f86967ca36508047dde032164c1dc91c4ac65ee981336",16);
  end

  it "Check Horizen parameters" do 
    triton = Poseidon.new_horizen();
    trident = PoseidonParams.new();
    trident.set_horizen_params();
    a = [5_u8,3_u8,44_u8];
    h= triton.hash(a , 32, trident);
    h.size().should eq 32;
  end


  it "check conversions" do
    #Convert to/from byte/field
    a = gen_test_arrays(100);
    a.each do |b|
      f = Poseidon.bytes_to_field(b);
      bb = Poseidon.field_to_bytes(f);
      while b[0] == 0
        b.shift
      end
      bb.should eq b;

      ff = Poseidon.bytes_to_field(bb);
      ff.should eq f;
    end

    #check horizen big_int representation
    ba = [
      "D90776E240000001",
      "4EA099170FA13A4F",
      "D6C381BC3F005797",
      "B9DFF97634993AA4",
      "3EEBCA9429212636",
      "B26C5C28C859A99B",
      "99D124D9A15AF79D",
      "07FDB925E8A0ED8D",
      "5EB7E8F96C97D873",
      "B7F997505B8FAFED",
      "10229022EEE2CDAD",
      "01C4C62D92C411",
  ]
      p = BigInt.new("41898490967918953402344214791240637128170709919953949071783502921025352812571106773058893763790338921418070971888458477323173057491593855069696241854796396165721416325350064441470418137846398469611935719059908164220784476160001")
      p.should eq PoseidonParams.str16a_to_big_int(ba);
  end


  it "custom hash" do 
    prime = BigInt.new("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",16);
    triton = Poseidon.new(prime, 128);
    alpha = -1;
    if (prime-1 % 5 != 0)
      alpha = 5
    elsif (prime-1 % 3 != 0)
      alpha = 3
    end
    trident = PoseidonParams.new();
    trident.set_params(prime, alpha, 8,57,3);
    trident.init_generator()
    trident.generate_constants(1, 254, 3, 8, 57, prime);
    a = gen_test_arrays(100);
    a.each do |b|
      triton.hash(b, 32, trident);
    end
  end

  it "perf" do 
    prime = BigInt.new("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",16);
    triton = Poseidon.new(prime, 128);
  trident = triton.auto_parameters#  trident = PoseidonParams.new();
  #  trident.set_params(prime, 5, 8,57,3);
 #   trident.init_generator()
  #  trident.generate_constants(1, 254, 3, 8, 57, prime);
 #   p = BigInt.new("41898490967918953402344214791240637128170709919953949071783502921025352812571106773058893763790338921418070971888458477323173057491593855069696241854796396165721416325350064441470418137846398469611935719059908164220784476160001")
 #   triton = Poseidon.new(p, 0 , 3 , 1)
 #   trident = PoseidonParams.new();
 #   trident.set_horizen_params();

    a = gen_test_arrays(1000,1000);
    t1 = Time.monotonic
    a.each do |b|
      h = triton.hash(b, 32, trident);
    end
    t2 = Time.monotonic
    pp "poseidon duration (#{a.size}):"
    pp (t2-t1).total_seconds

    t1 = Time.monotonic
    a.each do |b|
      ms = Slice.new(b.to_unsafe, b.size)
      hash = OpenSSL::Digest.new("SHA256")
      hash.update(ms)
      h = hash.hexdigest
    end
    t2 = Time.monotonic
    pp "sha256 duration:"
    pp (t2-t1).total_seconds
  end 

  it "basic_hash" do
    prime = BigInt.new("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",16);
    bob = Poseidon.new(prime, 128);
    params = bob.auto_parameters(128);
    a = [5_u8,3_u8,44_u8];
    h = bob.hash(a, 8, params);
    h.size().should eq 8
  end

  it "try generator" do 
    prime = BigInt.new("30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001",16);
    alpha = -1;
    if (prime-1 % 5 != 0)
      alpha = 5
    elsif (prime-1 % 3 != 0)
      alpha = 3
    end
    m_bits = 128 

    trident = PoseidonParams.new();
    trident.set_params(prime, alpha, 8, 59, 2);
    trident.init_generator()
    (0...20).each do |i|
      trident.generate_grain()
    end
  end

end

