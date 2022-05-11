#include "TestSDS.h"

int PrintData(char *itemName, unsigned char *sourceData, unsigned int dataLength, unsigned int rowCount)
{
	int i, j;
	
	if((sourceData == NULL) || (rowCount == 0) || (dataLength == 0))
		return -1;
	
	if(itemName != NULL)
		printf("%s[%d]:\n", itemName, dataLength);
	
	for(i=0; i<(int)(dataLength/rowCount); i++)
	{
		printf("%08x  ",i * rowCount);

		for(j=0; j<(int)rowCount; j++)
		{
			printf("%02x ", *(sourceData + i*rowCount + j));
		}

		printf("\n");
	}

	if (!(dataLength % rowCount))
		return 0;
	
	printf("%08x  ", (dataLength/rowCount) * rowCount);

	for(j=0; j<(int)(dataLength%rowCount); j++)
	{
		printf("%02x ",*(sourceData + (dataLength/rowCount)*rowCount + j));
	}

	printf("\n");

	return 0;
}

unsigned int FileWrite(char *filename, char *mode, unsigned char *buffer, size_t size)
{
	FILE *fp;
	unsigned int rw,rwed;

	if((fp = fopen(filename, mode)) == NULL ) 
	{
		return 0;
	}

	rwed = 0;

	while(size > rwed)
	{
		if((rw = (unsigned int)fwrite(buffer + rwed, 1, size - rwed, fp)) <= 0)
		{
			break;
		}

		rwed += rw;
	}

	fclose(fp);

	return rwed;
}

unsigned int FileRead(char *filename, char *mode, unsigned char *buffer, size_t size)
{
	FILE *fp;
	unsigned int rw, rwed;

	if((fp = fopen(filename, mode)) == NULL)
	{
		return 0;
	}

	rwed = 0;

	while((!feof(fp)) && (size > rwed))
	{
		if((rw = (unsigned int)fread(buffer + rwed, 1, size - rwed, fp)) <= 0)
		{
			break;
		}

		rwed += rw;
	}

	fclose(fp);

	return rwed;
}

#ifndef WIN32
int getch_unix(void)
{
  struct termios oldt, newt;
  int ch;

  tcgetattr( 0, &oldt );

  newt = oldt;

  newt.c_lflag &= ~( ICANON | ECHO );

  tcsetattr( 0, TCSANOW, &newt );

  ch = getchar();

  tcsetattr( 0, TCSANOW, &oldt );

  return ch;
}
#endif

int GetString(char *str, int maxSize)
{
	int ch = 0;
	int i = 0;

	str[0] = '\0';

POSITION_1:

	while(1)
	{
		ch = GETCH();

		if((ch == 'e') || (ch == 'E') || (ch == 'q') || (ch == 'Q'))
		{
			PUTCH(ch);
			str[i++] = ch;
			str[i] = 0;

			ch = GETCH();

			if((ch == '\n') || (ch == '\r'))
			{
				str[--i] = 0;
				return OPT_EXIT;
			}
			else if((ch == '\b') || (ch == 127))
			{
				printf("\b \b");

				str[--i] = 0;

				continue;
			}
			else
			{
				break;
			}
		}
		else if((ch == 'r') || (ch == 'R') || (ch == 'B') || (ch == 'b'))
		{
			PUTCH(ch);
			str[i++] = ch;
			str[i] = 0;

			ch = GETCH();

			if((ch == '\n') || (ch == '\r'))
			{
				str[--i] = 0;
				return OPT_RETURN;
			}
			else if((ch == '\b') || (ch == 127))
			{
				printf("\b \b");

				str[--i] = 0;

				continue;
			}
			else
			{
				break;
			}
		}
		else if((ch == 'P') || (ch == 'p'))
		{
			PUTCH(ch);
			str[i++] = ch;
			str[i] = 0;

			ch = GETCH();

			if((ch == '\n') || (ch == '\r'))
			{
				str[--i] = 0;
				return OPT_PREVIOUS;
			}
			else if((ch == '\b') || (ch == 127))
			{
				printf("\b \b");

				str[--i] = 0;

				continue;
			}
			else
			{
				break;
			}
		}
		else if((ch == 'n') || (ch == 'N') || (ch == '\n') || (ch == '\r'))
		{
			if((ch == '\n') || (ch == '\r'))
			{
				return OPT_NEXT;
			}
			else
			{
				PUTCH(ch);
				str[i++] = ch;
				str[i] = 0;
			}

			ch = GETCH();

			if((ch == '\n') || (ch == '\r'))
			{
				str[--i] = 0;
				return OPT_NEXT;
			}
			else if((ch == '\b') || (ch == 127))
			{
				printf("\b \b");

				str[--i] = 0;

				continue;
			}
			else
			{
				break;
			}
		}
		else if((ch == 'c') || (ch == 'C') )
		{
			PUTCH(ch);
			str[i++] = ch;
			str[i] = 0;

			ch = GETCH();

			if((ch == '\n') || (ch == '\r'))
			{
				str[--i] = 0;
				return OPT_CANCEL;
			}
			else if((ch == '\b') || (ch == 127))
			{
				printf("\b \b");

				str[--i] = 0;

				continue;
			}
			else
			{
				break;
			}
		}
		else if ((ch == '\b') || (ch == 127))
		{
			continue;
		}
		else
		{
			break;
		}
	}

	PUTCH(ch);
	str[i++] = ch;
	str[i] = 0;

	while(1)
    {
		ch = GETCH();

		if((ch == '\n') || (ch == '\r'))
		{
			if(i == 0)
			{
				return OPT_NEXT;
			}
			else
			{
				break;
			}
		}
        else if((ch == '\b') || (ch == 127))
        {
			if(i != 0)
			{
				printf("\b \b");

				str[--i] = 0;
			}
			else
			{
				goto POSITION_1;
			}
        }
        else
        {
            PUTCH(ch);
            str[i++] = ch;
            str[i] = 0;
        }
    }

	return i;
}

int GetPasswd(char *buf, int maxSize)
{
    int t;
    int i = 0;

    buf[0] = 0;

POSITION_1:

	while(1)
	{
		t = GETCH();

		if((t == 'e') || (t == 'E') || (t == 'q') || (t == 'Q'))
		{
			PUTCH('*');
			buf[i++] = t;
			buf[i] = 0;

			t = GETCH();

			if((t == '\n') || (t == '\r'))
			{
				buf[--i] = 0;
				return OPT_EXIT;
			}
			else if((t == '\b') || (t == 127))
			{
				printf("\b \b");

				buf[--i] = 0;

				continue;
			}
			else
			{
				break;
			}
		}
		else if((t == 'r') || (t == 'R') || (t == 'B') || (t == 'b'))
		{
			PUTCH('*');
			buf[i++] = t;
			buf[i] = 0;

			t = GETCH();

			if((t == '\n') || (t == '\r'))
			{
				buf[--i] = 0;
         		return OPT_RETURN;
			}
			else if((t == '\b') || (t == 127))
			{
				printf("\b \b");

				buf[--i] = 0;

				continue;
			}
			else
			{
				break;
			}
		}
		else if((t == 'P') || (t == 'p'))
		{
			PUTCH('*');
			buf[i++] = t;
			buf[i] = 0;

			t = GETCH();

			if((t == '\n') || (t == '\r'))
			{
				buf[--i] = 0;
         		return OPT_PREVIOUS;
			}
			else if((t == '\b') || (t == 127))
			{
				printf("\b \b");

				buf[--i] = 0;

				continue;
			}
			else
			{
				break;
			}
		}
		else if((t == 'n') || (t == 'N') || (t == '\n') || (t == '\r'))
		{
			if((t == '\n') || (t == '\r'))
			{
				return OPT_NEXT;
			}
			else
			{
				PUTCH('*');
				buf[i++] = t;
				buf[i] = 0;
			}

			t = GETCH();

			if((t == '\n') || (t == '\r'))
			{
				buf[--i] = 0;
			    return OPT_NEXT;
			}
			else if((t == '\b') || (t == 127))
			{
				printf("\b \b");

				buf[--i] = 0;
				
				continue;
			}
			else
			{
				break;
			}		
		}
		else if((t == 'c') || (t == 'C') )
		{
			PUTCH('*');
			buf[i++] = t;
			buf[i] = 0;

			t = GETCH();

			if((t == '\n') || (t == '\r'))
			{
				buf[--i] = 0;
			    return OPT_CANCEL;
			}
			else if((t == '\b') || (t == 127))
			{
				printf("\b \b");

				buf[--i] = 0;

				continue;
			}
			else
			{
				break;
			}
		}
		else if ((t == '\b') || (t == 127))
		{
			continue;
		}
		else
		{
			break;
		}
	}

	PUTCH('*');
	buf[i++] = t;
	buf[i] = 0;

	while(1)
    {
		t = GETCH();

		if((t == '\n') || (t == '\r'))
		{
			if(i == 0)
			{
				return OPT_NEXT;
			}
			else
			{
				break;
			}
		}
        else if((t == '\b') || (t == 127))
        {
			if(i != 0)
			{
				printf("\b \b");

				buf[--i] = 0;
			}
			else
			{
				goto POSITION_1;
			}
        }
        else
        {
            PUTCH('*');
            buf[i++] = t;
            buf[i] = 0;
        }
    }

	return i;
}

int GetSelect(int nDefaultSelect, int nMaxSelect)
{
	int rv;
	char str[256] = {0};
	int num;
	char *p = NULL;

	rv = GetString(str, sizeof(str));
	if((rv == OPT_EXIT) || (rv == OPT_RETURN) || (rv == OPT_PREVIOUS) || (rv == OPT_CANCEL) || (rv == OPT_NEXT))
	{
		if(rv == OPT_NEXT)
		{
			return nDefaultSelect;
		}		
		else
		{
			return rv;
		}
	}
	else
	{
		//遍历检查字符串
		for(p=str; p<str+strlen(str); p++)
		{
			if(!isdigit(*p))
			{
				//无效的输入参数

				return OPT_CANCEL; //此处改动，尽量保证了程序的前后兼容性
			}
		}

		num = atoi(str);

		if((num < 0) || (num > nMaxSelect))
		{
			//无效的输入参数

			return OPT_CANCEL; //此处改动，尽量保证了程序的前后兼容性
		}
		else
		{
			return num;
		}
	}

	return nDefaultSelect;
}

int GetInputLength(int nDefaultLength, int nMin, int nMax)
{
	int rv;
	char str[256] = {0};
	int num;
	char *ptr;

	rv = GetString(str, sizeof(str));
	if((rv == OPT_EXIT) || (rv == OPT_RETURN) || (rv == OPT_PREVIOUS) || (rv == OPT_CANCEL) || (rv == OPT_NEXT))
	{
		if(rv == OPT_NEXT)
		{
			return nDefaultLength;
		}		
		else
		{
			return rv;
		}
	}
	else
	{
		//遍历检查字符串
		for(ptr=str; ptr<str+strlen(str); ptr++)
		{
			if(!isdigit(*ptr))
			{
				//无效的输入参数

				return OPT_CANCEL;
			}
		}

		num = atoi(str);

		if((num < nMin) || (num > nMax))
		{
			//无效的输入参数

			return OPT_CANCEL;
		}
		else
		{
			return num;
		}
	}

	return nDefaultLength;
}

void GetAnyKey()
{
	int ch;

	ch = GETCH();

	return;
}
