/*
 * Copyright 2022 Post CH Ltd
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ch.post.it.evoting.cryptoprimitives.internal.mixnet;

import static ch.post.it.evoting.cryptoprimitives.math.GqElement.GqElementFactory;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import java.math.BigInteger;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import ch.post.it.evoting.cryptoprimitives.internal.hashing.HashService;
import ch.post.it.evoting.cryptoprimitives.math.GqElement;
import ch.post.it.evoting.cryptoprimitives.math.GqGroup;
import ch.post.it.evoting.cryptoprimitives.securitylevel.SecurityLevelConfig;
import ch.post.it.evoting.cryptoprimitives.test.tools.data.GroupTestData;
import ch.post.it.evoting.cryptoprimitives.test.tools.generator.GqGroupGenerator;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.JsonData;
import ch.post.it.evoting.cryptoprimitives.test.tools.serialization.TestParameters;

class CommitmentKeyServiceTest {

	private static GqGroupGenerator generator;
	private static CommitmentKeyService commitmentKeyService;
	private static GqGroup gqGroup;

	private GqElement h;
	private List<GqElement> gs;

	@BeforeAll
	static void setUpAll() throws NoSuchAlgorithmException {
		gqGroup = GroupTestData.getGqGroup();
		generator = new GqGroupGenerator(gqGroup);
		final HashService hashService = HashService.getInstance();
		commitmentKeyService = new CommitmentKeyService(hashService);
	}

	@BeforeEach
	void setUp() {
		h = generator.genNonIdentityNonGeneratorMember();
		gs = Stream.generate(generator::genNonIdentityNonGeneratorMember).limit(10).collect(Collectors.toList());
	}

	@Test
	@DisplayName("contains the correct commitment key")
	void constructionTest() {
		final CommitmentKey commitmentKey = new CommitmentKey(h, gs);

		assertEquals(h, commitmentKey.stream().limit(1).toList().get(0));
		assertEquals(gs, commitmentKey.stream().skip(1).collect(Collectors.toList()));
	}

	@Test
	void constructionFromNullParameterTest() {
		assertThrows(NullPointerException.class, () -> new CommitmentKey(null, gs));
		assertThrows(NullPointerException.class, () -> new CommitmentKey(h, null));

		final List<GqElement> gList = new ArrayList<>(gs);
		gList.add(null);
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, gList));
	}

	@Test
	void constructionWithEmptyListTest() {
		final List<GqElement> emptyList = new LinkedList<>();
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, emptyList));
	}

	@Test
	void constructionWithElementsFromDifferentGroupsTest() {
		final List<GqElement> elements = new LinkedList<>(gs);
		final GqGroup differentGroup = GroupTestData.getDifferentGqGroup(h.getGroup());
		final GqGroupGenerator differentGroupGenerator = new GqGroupGenerator(differentGroup);
		elements.add(differentGroupGenerator.genNonIdentityNonGeneratorMember());

		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, elements));
	}

	@Test
	void constructionWithHAndGFromDifferentGroupsTest() {
		final GqGroup differentGroup = GroupTestData.getDifferentGqGroup(h.getGroup());
		final GqGroupGenerator differentGroupGenerator = new GqGroupGenerator(differentGroup);
		final List<GqElement> gList = Stream.generate(differentGroupGenerator::genNonIdentityNonGeneratorMember).limit(3)
				.collect(Collectors.toList());
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, gList));
	}

	@Test
	void constructionWithIdentityTest() {
		final GqElement identity = h.getGroup().getIdentity();
		final List<GqElement> elementsWithIdentity = new LinkedList<>(gs);
		elementsWithIdentity.add(identity);

		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(identity, gs));
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, elementsWithIdentity));
	}

	@Test
	void constructionWithGeneratorTest() {
		final GqElement generator = h.getGroup().getGenerator();
		final List<GqElement> elementsWithIdentity = new LinkedList<>(gs);
		elementsWithIdentity.add(generator);

		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(generator, gs));
		assertThrows(IllegalArgumentException.class, () -> new CommitmentKey(h, elementsWithIdentity));
	}

	@Test
	void getVerifiableCommitmentKey() {

		final int numberOfCommitmentElements = 15;
		final GqGroup gqGroup = GroupTestData.getLargeGqGroup();
		final CommitmentKey verifiableCommitmentKey = commitmentKeyService.getVerifiableCommitmentKey(numberOfCommitmentElements, gqGroup);

		assertNotNull(verifiableCommitmentKey.getGroup());

		final GqElement h = GqElementFactory.fromValue(new BigInteger(
						"4249322945627563810920149791208209761639986360980202078672322801243822786539683941498887715884017849356835609556966093686837645088491997482552729491378723501989877394742388851322654755038850955863458577698774254368280552028892281925196704820925332889301872397358133550532294284763982929216768379859507831525212755139528495891980160880175301821865141384581640399375069830771410177678518130501304320565387814163269247540093619721044973185623590025929726088983585472820337015905016767887159795454673828886140928886664147563502546351156899861648208229024915216290511152617657687208140794929244976409736269453616202044094"),
				gqGroup);

		final List<GqElement> gqElements = Arrays.asList(
				GqElementFactory.fromValue(new BigInteger(
								"12853299231950473241983767103747246723021952666161274486167169609278335692639603929820529040177624472320019299148641229053026356267394402065404955015206326310014217026521561609233619574546975312724376233183994083727341419371670856112755728247225637622517053965567212714555403109185786569113334372213978626267384514597044850322959353233884636591494156825816310960429400944276782358863063139370617991586882623432137094626698346609547003161861811516375951121658977461450068827484301654619997948600210729237528006413617356873630978368634394595872860779246207176985343416211493036084835238702732428406300553881489438242485"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"12052102386973668959829577378616097328941193110409690203865729132671948409763512568130280903344195416549340314225211302277251282130642787679042783256165827757085572893833173276114271720746666605850932220856587559861456676033307375860228863108390253149280403120396415343556924042075242973847388132491782760949857879100987508258372658570288957051869609784112848096114407633238166565370442213723827512995402334793140022771476648323907943579008943771181622504031817224354572803733393232847044324669329079826747944085993816562036731554097395856936190797142576170037228522049238305718948079203777173245063361469974536237073"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"14397164791923792850274918963950864352917345008842211719055527212868979854555958422224393481266308712003735733406346305744551145852951579537112929268167236400947209030886004082476995562934030441116700541562364794774286077055671915992088250837005625805293195387370816076205744279288654269443029977748498255888617941169301394603365726344083076105929313127646023075100715451985568987216022650890819923295915381154059504700087584566039917566925781202687609516415911007741273772157486187656185280887673416118426088921207998190430145338719097468755817942429245522055794228950169943495025399959811314373441166767674129159903"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"19556875692590614381080520492830697156294866906935429868349233081486739790053510897550840022669293209805957805308026037176848388081524328678692623516899588791762329072238473091639592331995133194247311837729206861517763213186852513272464765333597268863099332009353105841337828264734083589359563394463908437038852534484855653537039470634029914079007283188592303019338685848708684029573747839824758981207838994974233447037645778870323220993624076877115033895532017119254388094151105719916975243521179476010408293674374179128728079551997481657633408473385238505072016970379890357471869855989618602022802065124892308514180"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"9530565790910952115741575997902821032829486820246525492992999944898326857835159186452581570358858045445450545121298392148150450615184637667574209865135234206334448050855229709783371146575202212334639510186738310132035039441305498407329062911787368197578860046451107994468078739183428588028631696499283492260536236937949442899887058531305469239424186401800779728013420813871243730914536652899575644903175334366041162255918435365830222890981533915058083904641335416989549373348333045441388482615019486690561507567513588927365723426129711405672746372093208884409219853774161494231696719041491450938522934219321975005958"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"5281122701671391929982778741562091152307062834892172040074925860372123532487383334273512954868289096547195943651544087246772893637812240772939540674522462739587161052684923518549375139508589466640225389037068805139711496221554759158627073170637776455264062438848056924773424827866622601627675686677229190089340041450980732295992824466319665661658344205665188385450631093679588119077646789485948388664368820526843311703412264750871277619178126224418914959742457768654014344625847077158494726821927750503376987916029702200906515000658845557279599816347746958991974614490588645502332404910156389298280653795410659835613"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"21356275726209382746424005218798035917274150822641328760306764050177252103602856673008434381969731612556017630211523767030424285006090709247187989082437646971468993960573451423382740381995018417729049897398474260118502839264116829235032787696897125663956510576560889100590824919296970279963470133792357807496841793985837217783592235456574555856989130011681465794625859041835652186912849294978359349254942569563266468750544212183709908202389013566466478053308807672316673467422865756199554109648743002526654516813791336685616492143301857902847139070544655723988057925414838020976982188969128693385829352363077808813095"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"22398793159163472187584414774081583295771341392831130435023381721436864114806234862193947289861261124776919018197694300341188243340235793837355913261314503180137393101731927710341165561665628458433878558063602595174896430501444958857589409455761276965182833366419619800382154129406125791301105976734378033031003393440873701897482748094256547629177769840272285681160702383006238760149376907229477602036424321761609844819359378548862485156616708951782504630234642114630978977122888825910151668546956771376399205180210291857372740114298572325055499580819998012764900417891335537917247842782229680226027132145859733589713"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"467475030617361315782403771715644515762999270177721517748710479684267909529891480977822182106069416156884347883335358380996304767784846968943264518883152254170292521153807969161086952777930531616975368939893363954280783909434798988813574954539214600061355755492284769187125198965764250343095929659293152349638113622165835402019262154190582951552441320812414475208710471149029129192691476994689600150661239509981623542193081246643538470666483500682791467177341170565462178536657210735297846331070538943870948642900932918053360675160931348100720355254054034846767429645134475886535160792592990802611207840067657333078"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"7849273584788403281280284581857215298729533403294678768643631434442962261419038586351785967090612128750385246619422703045237877287255223678365231964928126478859810783081660888377562203672291949653482910171054243805986495452111686103392729794552299756929247688282945578380240669319897515754939999387121633157304706545791237420592100246486149685732597832590749163884863871990151532665500868605174902179303556136708688100029441623901305611080716842973909003058331140695975792064821186530376166938457705402914727778967723897866129755142322165367772499543491066111490352718209995772856610795216867869263849859866217969001"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"9602452503263460150681574031096156703217160621233614015384676056669009193347925386382627632303464116184373281386025685796660077191468048378983269118977319727792165612070962437242097407810141656156525254322385594223102726946702218440886448413441358493444860950194029180570321125670788675941255944508829551523458416151501700708342036868213911153422229673281656098581682851119704421528637390020028706415251594641819418142738881399305876353058345287810979428513953807319530856391887523479497849928786266574526181110393131563293891854966696195919149107450254164285718295131497003139434134823118349455915901688045996452215"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"3281661201710506725631001264082462668428239089082825214618101811692224149841134593477172661452617030297011206171411357945386703464129459384605531516473276755871034846292366680758966517890682830070266449146559513561379592392362441207940807168042624620489629199983463464739356105991447702382840128522282268367943882167076805408711003920066068580156208716518097663804101506803047824851901289201023684759023157336731330921522478594724065019021792556290908838270032638107406291366832249460209295098573247863520838123209304165120690579291770729497715065733014779320081929514591580884309878144410937877533527367602083707684"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"3659224422709126438806315156019438692361935709001476046786050175479444970047541399499814833375487811810435674755039153435192469894354668804298393076465603089789985735827831277869131112514412738470757485145364492727737554745716016968047536175411770650354729844185944852875904558013172915912606920548575086998303975653909525888963544101598204474785805268035725788732608917829664426889414266405706027356839277105570955397732181444938086698814554061476383720803452368574502024489873353637525797833442096515942335623985054696338285350729226143263281829189165251046113239801442082776283922884975580432398309394065370600666"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"5663884307114507935915353214648677554142175026927169999323579337266349929492985037029794176577332701658591690642475962407653263953904426728836366663428341464154603686928990880268398868373007187262989341746010148500261770796209318198848945498816897976371327724136262301998663779419625543101949866418430157558721952778117556757435116582631747390641872692136956709834354517430213066339463693055088339652115886759564306787541292247613967829109327813950970285775485572004249109689215129320410934577339393899693918324652254777136976078836098773836749072340585560118816038850775789127944144042270895644946140669911687065050"),
						gqGroup),
				GqElementFactory.fromValue(new BigInteger(
								"10723786912277048780786719234434515663612651099227732920701048864222853120140690006473444693970561234609128526267278597834088751239165140946054291110719184856295182566571699212118677635927506049982906152695973850839028124477752049962230624322425714691400505677658844150788519539030737345224060120398733864970806757944367629004071895162878873834091658589609767797400499291288670998598489884099154287286589962381337771143140612087054103300326766904754699309033261282410049551388672461049985121932822958587817631172607265659625160593792274830222946697108018206730948271481630975892627508101392533334049979204536835056020"),
						gqGroup));

		final CommitmentKey expectedCommitmentKey = new CommitmentKey(h, gqElements);

		assertEquals(expectedCommitmentKey, verifiableCommitmentKey);
	}

	static Stream<Arguments> getVerifiableCommitmentKeyArgumentProvider() {
		final List<TestParameters> parametersList = TestParameters.fromResource("/mixnet/get-verifiable-commitment-key.json");

		return parametersList.stream().parallel().map(testParameters -> {
			// Context.
			final JsonData context = testParameters.getContext();
			final BigInteger p = context.get("p", BigInteger.class);
			final BigInteger q = context.get("q", BigInteger.class);
			final BigInteger g = context.get("g", BigInteger.class);

			try (final MockedStatic<SecurityLevelConfig> mockedSecurityLevel = Mockito.mockStatic(SecurityLevelConfig.class)) {
				mockedSecurityLevel.when(SecurityLevelConfig::getSystemSecurityLevel).thenReturn(testParameters.getSecurityLevel());
				final GqGroup gqGroup = new GqGroup(p, q, g);

				// Input.
				final JsonData input = testParameters.getInput();
				final int numberOfElements = input.get("k", Integer.class);

				// Output.
				final JsonData output = testParameters.getOutput();
				final GqElement h = GqElementFactory.fromValue(output.get("h", BigInteger.class), gqGroup);
				final List<GqElement> gVector = Arrays.stream(output.get("g", BigInteger[].class))
						.map(value -> GqElementFactory.fromValue(value, gqGroup))
						.collect(Collectors.toList());
				final CommitmentKey expectedCommitmentKey = new CommitmentKey(h, gVector);

				return Arguments.of(numberOfElements, gqGroup, expectedCommitmentKey, testParameters.getDescription());
			}
		});
	}

	@ParameterizedTest(name = "{3}")
	@MethodSource("getVerifiableCommitmentKeyArgumentProvider")
	@DisplayName("with real values")
	void getVerifiableCommitmentKeyRealValues(final int numberOfElements, final GqGroup gqGroup, final CommitmentKey expectedCommitmentKey,
			final String description) {

		final CommitmentKey verifiableCommitmentKey = commitmentKeyService.getVerifiableCommitmentKey(numberOfElements, gqGroup);

		assertEquals(expectedCommitmentKey, verifiableCommitmentKey, String.format("assertion failed for: %s", description));
	}

	@Test
	void testGetVerifiableCommitmentKeyThrowsOnTooSmallGroup() {
		final GqGroup group = GroupTestData.getGqGroup();
		final int size = group.getQ().subtract(BigInteger.valueOf(3)).add(BigInteger.ONE).intValueExact();
		assertThrows(IllegalArgumentException.class, () -> commitmentKeyService.getVerifiableCommitmentKey(size, group));
	}

	@Test
	void testGetVerifiableCommitmentKeyNullGpGroup() {
		assertThrows(NullPointerException.class, () -> commitmentKeyService.getVerifiableCommitmentKey(1, null));
	}

	@Test
	void testGetVerifiableCommitmentKeyIncorrectNumberOfCommitmentElements() {
		IllegalArgumentException illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> commitmentKeyService.getVerifiableCommitmentKey(0, gqGroup));
		assertEquals("The desired number of commitment elements must be in the range (0, q - 3]", illegalArgumentException.getMessage());

		illegalArgumentException = assertThrows(IllegalArgumentException.class,
				() -> commitmentKeyService.getVerifiableCommitmentKey(-1, gqGroup));

		assertEquals("The desired number of commitment elements must be in the range (0, q - 3]", illegalArgumentException.getMessage());
	}
}