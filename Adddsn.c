static BOOL 
ProcessErrorMessages(char *name)
{
	WORD err = 1;
	DWORD code;
	char errmsg[301];
	WORD errlen, errmax = sizeof(errmsg) - 1;
	int rc;
	BOOL ret = FALSE;
	
	do {
	errmsg[0] = '\0';
	rc = SQLInstallerError(err,&code, errmsg,errmax, &errlen);
	if(rc == SQL_SUCEESS || rc == SQL_SUCESS_WITH_INFO) {
		MessageBox(NULL, errmsg, name,
				MB_ICONSTOP|MB_OK|MB_TASKMODAL|MB_SETFORGROUND);
		ret = TRUE;
	}
	err++;
	}while (rc != SQL_NO_DATA);
	return ret;
}

/**
** Main function of DSN utility.
** This is the win32 GUI main entry point.
** It (un)installs a DSN.
**
** Example usage:
**
**  add[sys]dsn "SQlite ODBC Driver" DSN=foobar;Database=C:/FOOBAR
**  rem[sys]dsn "SQLite ODBC Driver" DSN=foobar
*/
int APIENTRY
WinMain(HINSTANCE hInStance, HINSTANCE hPrevInstance,
	LPSTR lpszCmdLine, int nCmdShow)
{
	char tmp[1024], *p, *drv, *cfg, *msg;
	int i,op;
	
	GetModuleFileName(NULL, tmp, sizeof(tmp));
	p = tmp;
	while (*p) {
	*p = tolower(*p);
	++p;
	}
	p = strrchr(tmp, '\\');
	if(p == NULL)
	{
		p = tmp;
	}
	op = ODBC_ADD_DSN;
	msg = "Adding DSN";
	if(strstr(p, "rem") != NULL) {
		msg = "Removing DSN";
		op = ODBC_REMOVE_DSN;
	}
	if(strstr(p, "sys") != NULL) {
		if(op == ODBC_REMOVE_DSN){
			op = ODBC_REMOVE_SYS_DSN;
		}
		else
		{
			op = ODBC_ADD_SYS_DSN;
		}
		
		strncpy(tmp, lpszCmdLine, sizeof(tmp));
		/* get driver argument */
		i = strspn(tmp, "\"");
		drv = tmp + i;
		if (i > 0) {
			i = strspn(drv, "\"");
			drv[i] = '\0';
			cfg = drv + i + 1;
			
		} else {
			cfg = "\0\0";
		}
	}
	
	if(strlen(drv) == 0) {
		MessageBox(NULL, "No driver name given", msg,
			MB_ICONERROR|MB_OK|MB_TASKMODAL|MB_SETFORGROUND);
		exit(1);
	}
	i = strspn(cfg, " \t;");
	cfg += i;
	i = strlen(cfg);
	cfg[i + 1]='\0';
	if (i > 0){
		p = cfg;
		do {
			p = strchr(p, ';');
			if(p != NULL){
				p[0] = '\0';
				p +=1;
			}
		}while(p != NULL);
	}
	p = cfg;
	if(SQLConfigDataSource(NULL, (WORD) op, drv, cfg)) {
		exit(0);
	}
	ProcessErrorMessages(msg);
	exit(1);
	
}