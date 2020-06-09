// +build windows

package wineventlog

import (
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestPayload_Value(t *testing.T) {
	// one null test
	originalHexStr := "3c004500760065006e007400200078006d006c006e0073003d00270068007400740070003a002f002f0073006300680065006d00610073002e006d006900630072006f0073006f00660074002e0063006f006d002f00770069006e002f0032003000300034002f00300038002f006500760065006e00740073002f006500760065006e00740027003e003c00530079007300740065006d003e003c00500072006f007600690064006500720020004e0061006d0065003d0027004d006900630072006f0073006f00660074002d00570069006e0064006f00770073002d00530065006300750072006900740079002d004100750064006900740069006e0067002700200047007500690064003d0027007b00350034003800340039003600320035002d0035003400370038002d0034003900390034002d0041003500420041002d003300450033004200300033003200380043003300300044007d0027002f003e003c004500760065006e007400490044003e0034003600320035003c002f004500760065006e007400490044003e003c00560065007200730069006f006e003e0030003c002f00560065007200730069006f006e003e003c004c006500760065006c003e0030003c002f004c006500760065006c003e003c005400610073006b003e00310032003500340034003c002f005400610073006b003e003c004f00700063006f00640065003e0030003c002f004f00700063006f00640065003e003c004b006500790077006f007200640073003e003000780038003000310030003000300030003000300030003000300030003000300030003c002f004b006500790077006f007200640073003e003c00540069006d00650043007200650061007400650064002000530079007300740065006d00540069006d0065003d00270032003000310039002d00300035002d00300035005400320033003a00310032003a00330037002e003300340039003400370036003100300030005a0027002f003e003c004500760065006e0074005200650063006f0072006400490044003e003600390034003600370034003c002f004500760065006e0074005200650063006f0072006400490044003e003c0043006f007200720065006c006100740069006f006e00200041006300740069007600690074007900490044003d0027007b00320035003200320035004600410031002d0044004100420039002d0030003000300031002d0041003600350046002d003200320032003500420039004400410044003400300031007d0027002f003e003c0045007800650063007500740069006f006e002000500072006f006300650073007300490044003d00270038003000340027002000540068007200650061006400490044003d002700310030003800300027002f003e003c004300680061006e006e0065006c003e00530065006300750072006900740079003c002f004300680061006e006e0065006c003e003c0043006f006d00700075007400650072003e0045004300320041004d0041005a002d0035004a00360049004600530046003c002f0043006f006d00700075007400650072003e003c00530065006300750072006900740079002f003e003c002f00530079007300740065006d003e003c004500760065006e00740044006100740061003e003c00440061007400610020004e0061006d0065003d0027005300750062006a00650063007400550073006500720053006900640027003e0053002d0031002d0030002d0030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027005300750062006a0065006300740055007300650072004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027005300750062006a0065006300740044006f006d00610069006e004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027005300750062006a006500630074004c006f0067006f006e004900640027003e003000780030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d002700540061007200670065007400550073006500720053006900640027003e0053002d0031002d0030002d0030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270054006100720067006500740055007300650072004e0061006d00650027003e00410044004d0049004e004900530054005200410054004f0052003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270054006100720067006500740044006f006d00610069006e004e0061006d00650027003e003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270053007400610074007500730027003e0030007800630030003000300030003000360064003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004600610069006c0075007200650052006500610073006f006e0027003e002500250032003300310033003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270053007500620053007400610074007500730027003e0030007800630030003000300030003000360061003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004c006f0067006f006e00540079007000650027003e0033003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004c006f0067006f006e00500072006f0063006500730073004e0061006d00650027003e004e0074004c006d0053007300700020003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d002700410075007400680065006e007400690063006100740069006f006e005000610063006b006100670065004e0061006d00650027003e004e0054004c004d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270057006f0072006b00730074006100740069006f006e004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027005400720061006e0073006d00690074007400650064005300650072007600690063006500730027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004c006d005000610063006b006100670065004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004b00650079004c0065006e0067007400680027003e0030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d002700500072006f0063006500730073004900640027003e003000780030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d002700500072006f0063006500730073004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270049007000410064006400720065007300730027003e003100340036002e00350036002e0036002e003100360036003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004900700050006f007200740027003e0030003c002f0044006100740061003e003c002f004500760065006e00740044006100740061003e003c002f004500760065006e0074003e000000"
	data, _ := hex.DecodeString(originalHexStr)
	bufferUsed := len(data)
	bytes, _ := UTF16ToUTF8Bytes(data, uint32(bufferUsed))
	str := string(bytes[:])
	assert.Equal(t, "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2019-05-05T23:12:37.349476100Z'/><EventRecordID>694674</EventRecordID><Correlation ActivityID='{25225FA1-DAB9-0001-A65F-2225B9DAD401}'/><Execution ProcessID='804' ThreadID='1080'/><Channel>Security</Channel><Computer>EC2AMAZ-5J6IFSF</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>ADMINISTRATOR</Data><Data Name='TargetDomainName'></Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp </Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>-</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>146.56.6.166</Data><Data Name='IpPort'>0</Data></EventData></Event>", str)

	// odd bytes test
	originalHexStr = "3c004500760065006e007400200078006d006c006e0073003d00270068007400740070003a002f002f0073006300680065006d00610073002e006d006900630072006f0073006f00660074002e0063006f006d002f00770069006e002f0032003000300034002f00300038002f006500760065006e00740073002f006500760065006e00740027003e003c00530079007300740065006d003e003c00500072006f007600690064006500720020004e0061006d0065003d0027004d006900630072006f0073006f00660074002d00570069006e0064006f00770073002d00530065006300750072006900740079002d004100750064006900740069006e0067002700200047007500690064003d0027007b00350034003800340039003600320035002d0035003400370038002d0034003900390034002d0041003500420041002d003300450033004200300033003200380043003300300044007d0027002f003e003c004500760065006e007400490044003e0034003600320035003c002f004500760065006e007400490044003e003c00560065007200730069006f006e003e0030003c002f00560065007200730069006f006e003e003c004c006500760065006c003e0030003c002f004c006500760065006c003e003c005400610073006b003e00310032003500340034003c002f005400610073006b003e003c004f00700063006f00640065003e0030003c002f004f00700063006f00640065003e003c004b006500790077006f007200640073003e003000780038003000310030003000300030003000300030003000300030003000300030003c002f004b006500790077006f007200640073003e003c00540069006d00650043007200650061007400650064002000530079007300740065006d00540069006d0065003d00270032003000310039002d00300035002d00300035005400320033003a00310032003a00330037002e003300340039003400370036003100300030005a0027002f003e003c004500760065006e0074005200650063006f0072006400490044003e003600390034003600370034003c002f004500760065006e0074005200650063006f0072006400490044003e003c0043006f007200720065006c006100740069006f006e00200041006300740069007600690074007900490044003d0027007b00320035003200320035004600410031002d0044004100420039002d0030003000300031002d0041003600350046002d003200320032003500420039004400410044003400300031007d0027002f003e003c0045007800650063007500740069006f006e002000500072006f006300650073007300490044003d00270038003000340027002000540068007200650061006400490044003d002700310030003800300027002f003e003c004300680061006e006e0065006c003e00530065006300750072006900740079003c002f004300680061006e006e0065006c003e003c0043006f006d00700075007400650072003e0045004300320041004d0041005a002d0035004a00360049004600530046003c002f0043006f006d00700075007400650072003e003c00530065006300750072006900740079002f003e003c002f00530079007300740065006d003e003c004500760065006e00740044006100740061003e003c00440061007400610020004e0061006d0065003d0027005300750062006a00650063007400550073006500720053006900640027003e0053002d0031002d0030002d0030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027005300750062006a0065006300740055007300650072004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027005300750062006a0065006300740044006f006d00610069006e004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027005300750062006a006500630074004c006f0067006f006e004900640027003e003000780030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d002700540061007200670065007400550073006500720053006900640027003e0053002d0031002d0030002d0030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270054006100720067006500740055007300650072004e0061006d00650027003e00410044004d0049004e004900530054005200410054004f0052003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270054006100720067006500740044006f006d00610069006e004e0061006d00650027003e003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270053007400610074007500730027003e0030007800630030003000300030003000360064003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004600610069006c0075007200650052006500610073006f006e0027003e002500250032003300310033003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270053007500620053007400610074007500730027003e0030007800630030003000300030003000360061003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004c006f0067006f006e00540079007000650027003e0033003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004c006f0067006f006e00500072006f0063006500730073004e0061006d00650027003e004e0074004c006d0053007300700020003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d002700410075007400680065006e007400690063006100740069006f006e005000610063006b006100670065004e0061006d00650027003e004e0054004c004d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270057006f0072006b00730074006100740069006f006e004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027005400720061006e0073006d00690074007400650064005300650072007600690063006500730027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004c006d005000610063006b006100670065004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004b00650079004c0065006e0067007400680027003e0030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d002700500072006f0063006500730073004900640027003e003000780030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d002700500072006f0063006500730073004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270049007000410064006400720065007300730027003e003100340036002e00350036002e0036002e003100360036003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004900700050006f007200740027003e0030003c002f0044006100740061003e003c002f004500760065006e00740044006100740061003e003c002f004500760065006e0074003e00000000"
	data, _ = hex.DecodeString(originalHexStr)
	bufferUsed = len(data)
	bytes, _ = UTF16ToUTF8Bytes(data, uint32(bufferUsed))
	str = string(bytes[:])
	assert.Equal(t, "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2019-05-05T23:12:37.349476100Z'/><EventRecordID>694674</EventRecordID><Correlation ActivityID='{25225FA1-DAB9-0001-A65F-2225B9DAD401}'/><Execution ProcessID='804' ThreadID='1080'/><Channel>Security</Channel><Computer>EC2AMAZ-5J6IFSF</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>ADMINISTRATOR</Data><Data Name='TargetDomainName'></Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp </Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>-</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>146.56.6.166</Data><Data Name='IpPort'>0</Data></EventData></Event>", str)

	// two nulls test
	originalHexStr = "3c004500760065006e007400200078006d006c006e0073003d00270068007400740070003a002f002f0073006300680065006d00610073002e006d006900630072006f0073006f00660074002e0063006f006d002f00770069006e002f0032003000300034002f00300038002f006500760065006e00740073002f006500760065006e00740027003e003c00530079007300740065006d003e003c00500072006f007600690064006500720020004e0061006d0065003d0027004d006900630072006f0073006f00660074002d00570069006e0064006f00770073002d00530065006300750072006900740079002d004100750064006900740069006e0067002700200047007500690064003d0027007b00350034003800340039003600320035002d0035003400370038002d0034003900390034002d0041003500420041002d003300450033004200300033003200380043003300300044007d0027002f003e003c004500760065006e007400490044003e0034003600320035003c002f004500760065006e007400490044003e003c00560065007200730069006f006e003e0030003c002f00560065007200730069006f006e003e003c004c006500760065006c003e0030003c002f004c006500760065006c003e003c005400610073006b003e00310032003500340034003c002f005400610073006b003e003c004f00700063006f00640065003e0030003c002f004f00700063006f00640065003e003c004b006500790077006f007200640073003e003000780038003000310030003000300030003000300030003000300030003000300030003c002f004b006500790077006f007200640073003e003c00540069006d00650043007200650061007400650064002000530079007300740065006d00540069006d0065003d00270032003000310039002d00300035002d00300035005400320033003a00310032003a00330037002e003300340039003400370036003100300030005a0027002f003e003c004500760065006e0074005200650063006f0072006400490044003e003600390034003600370034003c002f004500760065006e0074005200650063006f0072006400490044003e003c0043006f007200720065006c006100740069006f006e00200041006300740069007600690074007900490044003d0027007b00320035003200320035004600410031002d0044004100420039002d0030003000300031002d0041003600350046002d003200320032003500420039004400410044003400300031007d0027002f003e003c0045007800650063007500740069006f006e002000500072006f006300650073007300490044003d00270038003000340027002000540068007200650061006400490044003d002700310030003800300027002f003e003c004300680061006e006e0065006c003e00530065006300750072006900740079003c002f004300680061006e006e0065006c003e003c0043006f006d00700075007400650072003e0045004300320041004d0041005a002d0035004a00360049004600530046003c002f0043006f006d00700075007400650072003e003c00530065006300750072006900740079002f003e003c002f00530079007300740065006d003e003c004500760065006e00740044006100740061003e003c00440061007400610020004e0061006d0065003d0027005300750062006a00650063007400550073006500720053006900640027003e0053002d0031002d0030002d0030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027005300750062006a0065006300740055007300650072004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027005300750062006a0065006300740044006f006d00610069006e004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027005300750062006a006500630074004c006f0067006f006e004900640027003e003000780030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d002700540061007200670065007400550073006500720053006900640027003e0053002d0031002d0030002d0030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270054006100720067006500740055007300650072004e0061006d00650027003e00410044004d0049004e004900530054005200410054004f0052003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270054006100720067006500740044006f006d00610069006e004e0061006d00650027003e003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270053007400610074007500730027003e0030007800630030003000300030003000360064003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004600610069006c0075007200650052006500610073006f006e0027003e002500250032003300310033003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270053007500620053007400610074007500730027003e0030007800630030003000300030003000360061003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004c006f0067006f006e00540079007000650027003e0033003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004c006f0067006f006e00500072006f0063006500730073004e0061006d00650027003e004e0074004c006d0053007300700020003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d002700410075007400680065006e007400690063006100740069006f006e005000610063006b006100670065004e0061006d00650027003e004e0054004c004d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270057006f0072006b00730074006100740069006f006e004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027005400720061006e0073006d00690074007400650064005300650072007600690063006500730027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004c006d005000610063006b006100670065004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004b00650079004c0065006e0067007400680027003e0030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d002700500072006f0063006500730073004900640027003e003000780030003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d002700500072006f0063006500730073004e0061006d00650027003e002d003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d00270049007000410064006400720065007300730027003e003100340036002e00350036002e0036002e003100360036003c002f0044006100740061003e003c00440061007400610020004e0061006d0065003d0027004900700050006f007200740027003e0030003c002f0044006100740061003e003c002f004500760065006e00740044006100740061003e003c002f004500760065006e0074003e000000000000"
	data, _ = hex.DecodeString(originalHexStr)
	bufferUsed = len(data)
	bytes, _ = UTF16ToUTF8Bytes(data, uint32(bufferUsed))
	str = string(bytes[:])
	assert.Equal(t, "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Security-Auditing' Guid='{54849625-5478-4994-A5BA-3E3B0328C30D}'/><EventID>4625</EventID><Version>0</Version><Level>0</Level><Task>12544</Task><Opcode>0</Opcode><Keywords>0x8010000000000000</Keywords><TimeCreated SystemTime='2019-05-05T23:12:37.349476100Z'/><EventRecordID>694674</EventRecordID><Correlation ActivityID='{25225FA1-DAB9-0001-A65F-2225B9DAD401}'/><Execution ProcessID='804' ThreadID='1080'/><Channel>Security</Channel><Computer>EC2AMAZ-5J6IFSF</Computer><Security/></System><EventData><Data Name='SubjectUserSid'>S-1-0-0</Data><Data Name='SubjectUserName'>-</Data><Data Name='SubjectDomainName'>-</Data><Data Name='SubjectLogonId'>0x0</Data><Data Name='TargetUserSid'>S-1-0-0</Data><Data Name='TargetUserName'>ADMINISTRATOR</Data><Data Name='TargetDomainName'></Data><Data Name='Status'>0xc000006d</Data><Data Name='FailureReason'>%%2313</Data><Data Name='SubStatus'>0xc000006a</Data><Data Name='LogonType'>3</Data><Data Name='LogonProcessName'>NtLmSsp </Data><Data Name='AuthenticationPackageName'>NTLM</Data><Data Name='WorkstationName'>-</Data><Data Name='TransmittedServices'>-</Data><Data Name='LmPackageName'>-</Data><Data Name='KeyLength'>0</Data><Data Name='ProcessId'>0x0</Data><Data Name='ProcessName'>-</Data><Data Name='IpAddress'>146.56.6.166</Data><Data Name='IpPort'>0</Data></EventData></Event>", str)

}
