public class AccountController {
    public Account account { get; set; }

    public AccountController() {
        Id accId = ApexPages.currentPage().getParameters().get('id');
        if (accId != null) {
            account = [SELECT Id, Name, Industry, Type 
                       FROM Account 
                       WHERE Id = :accId 
                       LIMIT 1];
        }
    }
}
