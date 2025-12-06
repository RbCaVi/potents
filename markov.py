import collections
import random
import itertools

contextlen = 5

def markovchain(ts):
  s = ''
  num = 1
  denom = 1
  cs = collections.deque(maxlen = contextlen)
  while True:
    c = random.choice(ts[tuple(cs)])
    num *= ts[tuple(cs)].count(c)
    denom *= len(ts[tuple(cs)])
    cs.append(c)
    s += c
    if c == '':
      break
  return s, num, denom

def makemarkov(ss):
  ts = collections.defaultdict(list)
  for s in ss:
    cs = collections.deque(maxlen = contextlen)
    for c in s:
      ts[tuple(cs)].append(c)
      cs.append(c)
    ts[tuple(cs)].append('')
  return ts

ts = makemarkov([
	'https://tenor.com/view/makima-milky-subway-look-cute-gif-6317900141482170387',
	'https://tenor.com/view/danicon-le-le-gif-8144411121481074655',
	'https://tenor.com/view/memeline-estrogen-hrt-gif-8328437644082138814',
	'https://tenor.com/view/anaxa-hsr-honkai-star-rail-hsr-anaxa-anaxa-hsr-gif-3205839430420422915',
	'https://tenor.com/view/chat-dead-dead-chat-gif-3744420475329132384',
	'https://tenor.com/view/furry-protogen-boop-roblox-gif-22486741',
	'https://tenor.com/view/sus-suspicious-puss-in-boots-puss-in-boots-kitty-soft-paws-kitty-soft-paws-gif-27395636',
	'https://tenor.com/view/asriel-fade-gif-5391839970729608225',
	'https://tenor.com/view/corru-observer-corru-qou-get-this-man-a-shield-get-this-man-gif-13138028205385780778',
	'https://tenor.com/view/umbreon-we-back-at-it-again-trolling-imminent-groupchat-ubero-gif-12753035765329343852',
	'https://tenor.com/view/tax-fraud-gif-27523109',
	'https://tenor.com/view/discord-best-owner-bad-owner-ping-many-pings-gif-10740496253173180268',
	'https://tenor.com/view/gnarpy-regretevator-groovy-dance-roblox-regretavator-gif-11919463293422254570',
	'https://tenor.com/view/taxes-my-money-jcroat-crazy-taxes-roatcarljohn-gif-4889368921546559485',
	'https://tenor.com/view/no-gif-16448224600471793133',
	'https://tenor.com/view/angry-birds-red-dice-if-i-roll-gif-4407198540316116321',
	'https://tenor.com/view/rain-world-rain-world-watcher-the-watcher-gif-4275769679889501654',
	'https://tenor.com/view/plink-cat-cat-meme-clairen-rivals-gif-161723023160884901',
	'https://tenor.com/view/rainworld-slugcat-scug-kill-gif-1753473471008417503',
	'https://tenor.com/view/seb-cat-love-secret-society-cat-meme-gif-15496312',
	'https://tenor.com/view/genba-neko-cat-cooking-gif-12459546',
	'https://tenor.com/view/rat-wakes-up-gif-7924011165133281518',
	'https://tenor.com/view/omori-stairs-smooth-gif-20018210',
	'https://tenor.com/view/jakecord-minecraft-stairs-i-warned-you-gif-18367286',
	'https://tenor.com/view/v1-v-v1xv-md-ultrakill-gif-14550777334673695210',
	'https://tenor.com/view/goku-goku-angry-future-christmas-gif-8986089928564770350',
	'https://tenor.com/view/goku-goku-angry-future-christmas-gif-8986089928564770350',
	'https://tenor.com/view/consequences-cat-gif-6581548611274851813',
	'https://tenor.com/view/frog-attacker-jumpscare-frog-jumpscare-boo-gif-1410553638666856648',
	'https://tenor.com/view/resonite-hop-on-hop-on-resonite-crownedhaley-fox-gif-7183751197587528831',
	'https://tenor.com/view/asdf-spaghetti-spagety-asdf-movie-gif-25134601',
	'https://tenor.com/view/hornet-handling-european-hornet-insect-wasp-gif-14606516373128649015',
	'https://tenor.com/view/woa2kai-gif-446270096290500835',
	'https://tenor.com/view/the-flying-dutchmen-rule-2-rules-begging-gif-16855301295019750791',
	'https://tenor.com/view/looking-protogen-kaj-meme-furry-gif-23378472',
	'https://tenor.com/view/amor-gif-10758667656717415642',
	'https://tenor.com/view/nikola-tesla-theres-so-much-bees-theres-so-much-porn-theres-so-much-bart-theres-so-much-nikola-tesla-gif-18437059001493364427',
	'https://tenor.com/view/homestuck-gif-25318826',
	'https://tenor.com/view/vegeta-majin-vegeta-dragon-ball-legends-dragon-dragon-ball-z-gif-16608221371907468706',
	'https://tenor.com/view/weeb-touching-gif-25165375',
	'https://tenor.com/view/johnny-cage-mk1-mortal-kombat-1-johnny-mk1-moi-gc-gif-16017187234290208322',
	'https://tenor.com/view/guts-and-blackpowder-gif-9367304251931080357',
	'https://tenor.com/view/electrocuted-fortitudo-avali-electric-chair-gif-15179603523857075253',
	'https://tenor.com/view/jimmy-urine-mindless-self-indulgence-msi-chat-gif-7442951719062435768',
	'https://tenor.com/view/homestuck-tricketer-lovebug-gif-22903133',
	'https://tenor.com/view/duck-anime-gif-19849513',
	'https://tenor.com/view/off-script-offscript-gif-964775558182356485',
	'https://tenor.com/view/artifyber-artibun-death-minecraft-furry-gif-16855741541372622858',
	'https://tenor.com/view/limbus-company-project-moon-concept-incinerator-ltg-low-tier-god-gif-16559861299010394734',
	'https://tenor.com/view/furry-vr-boop-protogen-scary-gif-25615039',
	'https://tenor.com/view/rain-world-slugcat-gif-9668209685450225329',
	'https://tenor.com/view/mods-low-tier-god-ltg-gif-4022085103641635431',
	'https://tenor.com/view/polaroid-mama-boy-rw-rain-world-madness-gif-11202332736143575664',
	'https://tenor.com/view/roblox-block-tales-cruel-king-promotion-ice-dagger-gif-5077684881908901034',
	'https://tenor.com/view/roblox-block-tales-cruel-king-promotion-ice-dagger-gif-5077684881908901034',
	'https://tenor.com/view/sex-ronald-mcdonald-ifunny-gif-18050238',
	'https://tenor.com/view/deer-funny-eating-gif-4440560066269991308',
	'https://tenor.com/view/maxwell-maxwell-cat-maxwell-the-cat-laundry-doing-laundry-gif-9386017078935591047',
	'https://tenor.com/view/slot-machine-addicts-when-they-gif-27521413',
	'https://tenor.com/view/from-the-screen-to-the-ring-to-the-pen-to-the-king-beer-drunk-driving-ksi-funny-gif-9269358842148218939',
	'https://tenor.com/view/human-pattern-moving-formation-weaving-pattern-gif-17178109',
	'https://tenor.com/view/conductor-we-have-a-problem-cat-cute-funny-gif-17168115721186324165',
	'https://tenor.com/view/when-your-pizzais-here-gif-23324305',
	'https://tenor.com/view/roblox-block-tales-cruel-king-promotion-ice-dagger-gif-5077684881908901034',
	'https://tenor.com/view/rule-55-sonic-rule-55ignore-rule54-ignore-5-gif-9851655160031919794',
	'https://tenor.com/view/what-a-nice-pizza-what-a-nice-man-miles-edgeworth-shymain-aacj-gif-25872963',
	'https://tenor.com/view/mitski-omori-omori-basil-basil-omori-omori-mitski-gif-21339813',
	'https://tenor.com/view/sigma-i-feel-so-sigma-alien-stage-alien-stage-ivan-ivan-gif-10726452465458566077',
	'https://tenor.com/view/cat-silly-cat-goofy-kitty-review-boing-gif-17822439938117073146',
	'https://tenor.com/view/if-i-roll-gif-6684167966023799495',
	'https://tenor.com/view/hawk-tuah-meow-meow-gif-5958517323243578505',
	'https://tenor.com/view/get-stoned-go-go-loser-ranger-ranger-reject-sentai-daishikkaku-green-keeper-gif-445129537984914052',
	'https://tenor.com/view/bubble-speech-speech-discord-mod-meetup-discord-moderator-gif-26146459',
	'https://tenor.com/view/boy-kisser-boykisser-boy-kisser-speech-bubble-boykisser-speech-bubble-speech-bubble-gif-4169251036245788516',
	'https://tenor.com/view/trump-gif-7802426571414259207',
	'https://tenor.com/view/hello-chat-gojo-gif-25139184',
	'https://tenor.com/view/gojo-screenshot-jujutsu-kaisen-gojo-satoru-gojo-nah-id-win-gif-4087154782000543513',
	'https://tenor.com/view/heyyoha-tboi-sad-gif-1438788151179859553',
	'https://tenor.com/view/till-alien-stage-alnst-gif-11114852601296155091',
	'https://tenor.com/view/social-credit-raxdflipnote-flipnote-gif-4649943690202783735',
	'https://tenor.com/view/spongebob-mr-krabs-tally-hall-rob-cantor-any-price-i-set-theyll-pay-gif-7710624053841996238',
	'https://tenor.com/view/memes-gif-2222645606524605015',
	'https://tenor.com/view/skibidi-skibidi-toilet-jumpscare-skibidi-jumpscare-scary-skibidi-gif-3052949629825843595',
	'https://tenor.com/view/forsaken-roblox-two-time-soap-sigma-kids-gc-gif-13486236732836802054',
	'https://tenor.com/view/clear-aoba-dramatical-murder-noiz-mink-gif-9052281443112285412',
	'https://tenor.com/view/fortnite-hatsune-miku-hatsune-miku-hatsune-miku-fortnite-gif-10217030384507168811',
	'https://tenor.com/view/terezi-terezi-pyrope-homestuck-hom3stuck-libra-gif-952013295761444277',
	'https://tenor.com/view/acid-spoon-i-have-no-more-spoon-gif-14007313',
	'https://tenor.com/view/watch-yo-tone-content-warning-watch-yo-tone-cw-content-warning-cw-watch-gif-11662593216246043794',
	'https://tenor.com/view/ultra-kill-minos-prime-short-gif-7560026275295598805',
	'https://tenor.com/view/mgr-sam-thinking-omori-matpat-gif-24613652',
	'https://tenor.com/view/mgr-sam-thinking-omori-matpat-gif-24613652',
	'https://tenor.com/view/gojo-jjk-hollow-purple-yapping-yap-gif-11549699007778800962',
	'https://tenor.com/view/superzings-superthings-meme-ip-address-doxxed-gif-24424760',
	'https://tenor.com/view/my-honest-reaction-factorio-fishing-gif-16906335066699177672',
	'https://tenor.com/view/homestuck-rule1-tavros-gif-24622368',
	'https://tenor.com/view/watch-yo-tone-gif-26264295',
	'https://tenor.com/view/nepeta-homestuck-gif-23430751',
	'https://tenor.com/view/furry-put-finger-here-boop-gif-9038167',
	'https://tenor.com/view/basement-horror-kids-dark-game-gif-1623645817586195258',
	'https://tenor.com/view/ratatouille-ayo-the-pizza-here-me-in40years-ptsd-flashback-gif-21084849',
	'https://tenor.com/view/homestuck-gif-21356974',
	'https://tenor.com/view/don%27t-dm-me-don%27t-pregnant-man-react-me-we%27re-done-dirt-man-pregnant-sir-monster-pregnant-gif-374933367237774280',
	'https://tenor.com/view/frog-attacker-jumpscare-frog-jumpscare-boo-gif-1410553638666856648',
	'https://tenor.com/view/frog-attacker-jumpscare-frog-jumpscare-boo-gif-1410553638666856648',
	'https://tenor.com/view/frog-attacker-jumpscare-frog-jumpscare-boo-gif-1410553638666856648',
	'https://tenor.com/view/frog-attacker-jumpscare-frog-jumpscare-boo-gif-1410553638666856648',
	'https://tenor.com/view/mods-fill-his-stocking-with-bombsd-bombs-fill-his-stocking-with-bombs-christmas-gif-9317622027084449801',
	'https://tenor.com/view/furry-gif-5038661',
	'https://tenor.com/view/stw2-toaster-avali-scared-scared-meme-gif-9731949716134876672',
	'https://tenor.com/view/consequences-cat-gif-6581548611274851813',
	'https://tenor.com/view/smg4-bob-i-have-ovaries-gif-23088673',
	'https://tenor.com/view/rain-world-kissing-happy-new-year-2024-slugcat-gif-8713856522724907917',
	'https://tenor.com/view/vr-vrchat-gif-14017020064668294317',
	'https://tenor.com/view/ltg-low-tier-god-ltg-mods-mods-dox-gif-12807119010175108153',
	'https://tenor.com/view/omori-kel-omori-homestuck-gif-22373143',
	'https://tenor.com/view/doomspire-defense-roblox-scooter-vy-box-community-dd-gif-14386060379350201695',
	'https://tenor.com/view/jpegmafia-okbh-shark-park-gif-1299311271491651920',
	'https://tenor.com/view/moose-protogen-microwave-spin-furry-gif-23798646',
	'https://tenor.com/view/meme-gif-5654906203024776678',
	'https://tenor.com/view/logan-l-gif-5770331177887764102',
	'https://tenor.com/view/tifa-tifa-willem-gif-26563300',
	'https://tenor.com/view/marin-kitagawa-shy-kitagawa-marin-gif-10372929524112041228',
	'https://tenor.com/view/apple-google-samsung-samsung-galaxy-galaxy-s25-gif-355192212835583151',
	'https://tenor.com/view/smg4-joker-gif-13485142',
	'https://tenor.com/view/pov-discord-light-mode-flash-bang-light-gif-1426422483106098174',
	'https://tenor.com/view/tf2spy-he-could-be-any-one-of-us-gif-22141763',
	'https://tenor.com/view/imposter-tf2-it-could-be-you-it-could-be-me-spy-gif-23428031',
	'https://tenor.com/view/among-us-imposter-fnaf-spring-trap-gif-15054418844136658321',
	'https://tenor.com/view/i-am-no-use-to-anyone-supergirl-my-adventures-with-superman-there%27s-no-one-i-can-help-adult-swim-gif-11671186550455173118',
	'https://tenor.com/view/this-could-be-us-a-space-for-the-unbound-atma-raya-cinema-gif-12262408436260503599',
	'https://tenor.com/view/gypsy-crusader-sawcon-ligma-gif-23351753',
	'https://tenor.com/view/silver-the-hedgehog-you-are-the-reason-why-god-is-not-talking-to-us-anymore-roblox-sonic-the-hedgehog-sonic-06-gif-10384519053175919321',
	'https://tenor.com/view/hop-on-resonite-resonite-neosvr-hop-on-neos-neos-gif-10257836668807741418',
	'https://tenor.com/view/c-programming-segmentation-fault-segfault-gif-2148153610786238200',
	'https://tenor.com/view/roblox-block-tales-hatred-pk-thunder-love-is-in-the-air-gif-6162644865842462553',
	'https://tenor.com/view/sus-amongus-vrchat-avali-avali-army-gif-22156543',
	'https://tenor.com/view/transformers-prime-soundwave-dox-that-guy-gif-14468215162091763102',
	'https://tenor.com/view/bingus-epic-boss-meme-gif-14699694993734861091',
	'https://tenor.com/view/pluh-cat-cat-meme-caption-worldbox-gif-8990606681903386683',
	'https://tenor.com/view/avali-avali-nesi-stupid-gif-5838333740993563567',
	'https://tenor.com/view/duck-ducks-confused-surprised-what-gif-1845535727828628932',
	'https://tenor.com/view/skill-issue-gif-24412426',
	'https://tenor.com/view/batman-real-true-fact-checked-fact-gif-6343207587503842551',
	'https://tenor.com/view/bug-ok-leaf-water-drop-droplet-gif-27625340',
	'https://tenor.com/view/siege-tank-starcraft-brood-war-gif-14919612998139094857',
	'https://tenor.com/view/paper-mario-bowser-epic-embed-fail-gif-10415503456917741955',
	'https://tenor.com/view/splunger-isopod-rolly-poly-pill-bug-meme-gif-2092182872017611564',
	'https://tenor.com/view/discord-star-react-starboard-thanos-bread-guy-gif-16229764071099581782',
	'https://tenor.com/view/splunger-isopod-rolly-poly-pill-bug-meme-gif-2092182872017611564',
	'https://tenor.com/view/omori-omori-sunny-math-gif-25560756',
	'https://tenor.com/view/nepeta-microwave-peanut-butter-toes-homestuck-gif-26299950',
	'https://tenor.com/view/boyfriend-fnf-boyfriend-girlfriend-fnf-girlfriend-fnf-gif-2369835396796067000',
	'https://tenor.com/view/scp-gif-25493240',
	'https://tenor.com/view/olimist-scp-scp-sl-scp-secret-laboratory-secret-lab-gif-17078813376659131737',
	'https://tenor.com/view/ena-dream-bbq-dream-bbq-bouba-gif-1003937027669683527',
	'https://tenor.com/view/randy-avent-longboarding-florida-poly-fpu-phoenix-gif-1869786193098334111',
	'https://tenor.com/view/avali-wagging-tail-tail-wag-gif-7833592553460080976',
	'https://tenor.com/view/allosaurus-2-gif-10564772688717368381',
	'https://tenor.com/view/diddy-diddy-party-drake-gif-6172937771891016983',
	'https://tenor.com/view/epic-embed-fail-epic-fail-gif-8670027723805715741',
	'https://tenor.com/view/z-fighting-my-beloved-z-fighting-heart-locket-z-fighting-z-fighting-z-fighting-my-beloved-gif-5368919858407052397',
	'https://tenor.com/view/green-role-puke-role-monkey-roleist-rolecism-gif-3912651994190373386',
	'https://tenor.com/view/cope-sphere-inside-out-turning-a-sphere-inside-out-outside-in-how-to-turn-a-sphere-inside-out-gif-21417574',
])

with open('~/Downloads/log(2).txt') as f:
	ts = makemarkov([(line + '\n').rstrip('\n') for line in f])

def printmarkovs():
	#cond = lambda s: not (s.startswith('!') or s.startswith('?') or s.startswith('[['))
	cond = lambda s: s != '' and '[[' not in s and ']]' not in s
	for i,(s,num,denom) in zip(range(30), filter(lambda x: cond(x[0]), (markovchain(ts) for _ in itertools.count()))):
		#print(s, num / denom)
		print(s)


printmarkovs()