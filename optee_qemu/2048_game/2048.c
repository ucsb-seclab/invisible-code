/*
 ============================================================================
 Name        : 2048.c
 Author      : Maurits van der Schee
 Description : Console version of the game "2048" for GNU/Linux
 ============================================================================
 */

#define _XOPEN_SOURCE 500
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <termios.h>
#include <stdbool.h>
#include <stdint.h>
#include <time.h>
#include <signal.h>

#include <sys/wait.h>
#include <sys/time.h>

#include "2048.h"
#include "drm_setup.c"

uint32_t score=0;
uint8_t scheme=0;

unsigned int moves=0, divbombs=0, randbombs=0;
struct timespec tp2, tp_divs[MAX_MEASURES], tp_bombs[MAX_MEASURES];
time_t s;
long ns;

void getColor(uint8_t value, char *color, size_t length) {
	uint8_t original[] = {8,255,1,255,2,255,3,255,4,255,5,255,6,255,7,255,9,0,10,0,11,0,12,0,13,0,14,0,255,0,255,0};
	uint8_t blackwhite[] = {232,255,234,255,236,255,238,255,240,255,242,255,244,255,246,0,248,0,249,0,250,0,251,0,252,0,253,0,254,0,255,0};
	uint8_t bluered[] = {235,255,63,255,57,255,93,255,129,255,165,255,201,255,200,255,199,255,198,255,197,255,196,255,196,255,196,255,196,255,196,255};
	uint8_t *schemes[] = {original,blackwhite,bluered};
	uint8_t *background = schemes[scheme]+0;
	uint8_t *foreground = schemes[scheme]+1;
	if (value > 0) while (value--) {
		if (background+2<schemes[scheme]+sizeof(original)) {
			background+=2;
			foreground+=2;
		}
	}
	snprintf(color,length,"\033[38;5;%d;48;5;%dm",*foreground,*background);
}

void drawBoard(board_t board) {
	// instant tests lol :P
}

void drawsBoard(board_t board) {
	uint8_t x,y;
	char color[40], reset[] = "\033[m";
	printf("\033[H");

	printf("2048.c %17d pts\n\n",score);

	for (y=0;y<SIZE;y++) {
		for (x=0;x<SIZE;x++) {
			getColor(board[x][y],color,40);
			printf("%s",color);
			printf("       ");
			printf("%s",reset);
		}
		printf("\n");
		for (x=0;x<SIZE;x++) {
			getColor(board[x][y],color,40);
			printf("%s",color);
			if (board[x][y]!=0) {
				char s[8];
				snprintf(s,8,"%u",(uint32_t)1<<board[x][y]);
				uint8_t t = 7-strlen(s);
				printf("%*s%s%*s",t-t/2,"",s,t/2,"");
			} else {
				printf("   ·   ");
			}
			printf("%s",reset);
		}
		printf("\n");
		for (x=0;x<SIZE;x++) {
			getColor(board[x][y],color,40);
			printf("%s",color);
			printf("       ");
			printf("%s",reset);
		}
		printf("\n");
	}
	printf("\n");
	printf("←,↑,→,↓ q:quit 1:save 2:load\n");
	printf("\033[A"); // one line up
}

uint8_t findTarget(uint8_t array[SIZE],uint8_t x,uint8_t stop) {
	uint8_t t;
	// if the position is already on the first, don't evaluate
	if (x==0) {
		return x;
	}
	for(t=x-1;t>=0;t--) {
		if (array[t]!=0) {
			if (array[t]!=array[x]) {
				// merge is not possible, take next position
				return t+1;
			}
			return t;
		} else {
			// we should not slide further, return this one
			if (t==stop) {
				return t;
			}
		}
	}
	// we did not find a
	return x;
}

bool slideArray(uint8_t array[SIZE]) {
	bool success = false;
	uint8_t x,t,stop=0;

	for (x=0;x<SIZE;x++) {
		if (array[x]!=0) {
			t = findTarget(array,x,stop);
			// if target is not original position, then move or merge
			if (t!=x) {
				// if target is zero, this is a move
				if (array[t]==0) {
					array[t]=array[x];
				} else if (array[t]==array[x]) {
					// merge (increase power of two)
					array[t]++;
					// increase score
					score+=(uint32_t)1<<array[t];
					// set stop to avoid double merge
					stop = t+1;
				}
				array[x]=0;
				success = true;
			}
		}
	}
	return success;
}

void rotateBoard(board_t board) {
	uint8_t i,j,n=SIZE;
	uint8_t tmp;
	for (i=0; i<n/2; i++) {
		for (j=i; j<n-i-1; j++) {
			tmp = board[i][j];
			board[i][j] = board[j][n-i-1];
			board[j][n-i-1] = board[n-i-1][n-j-1];
			board[n-i-1][n-j-1] = board[n-j-1][i];
			board[n-j-1][i] = tmp;
		}
	}
}

bool moveUp(board_t board) {
	bool success = false;
	uint8_t x;
	for (x=0;x<SIZE;x++) {
		success |= slideArray(board[x]);
	}
	return success;
}

bool moveLeft(board_t board) {
	bool success;
	rotateBoard(board);
	success = moveUp(board);
	rotateBoard(board);
	rotateBoard(board);
	rotateBoard(board);
	return success;
}

bool moveDown(board_t board) {
	bool success;
	rotateBoard(board);
	rotateBoard(board);
	success = moveUp(board);
	rotateBoard(board);
	rotateBoard(board);
	return success;
}

bool moveRight(board_t board) {
	bool success;
	rotateBoard(board);
	rotateBoard(board);
	rotateBoard(board);
	success = moveUp(board);
	rotateBoard(board);
	return success;
}

bool findPairDown(board_t board) {
	bool success = false;
	uint8_t x,y;
	for (x=0;x<SIZE;x++) {
		for (y=0;y<SIZE-1;y++) {
			if (board[x][y]==board[x][y+1]) return true;
		}
	}
	return success;
}

uint8_t countEmpty(board_t board) {
	uint8_t x,y;
	uint8_t count=0;
	for (x=0;x<SIZE;x++) {
		for (y=0;y<SIZE;y++) {
			if (board[x][y]==0) {
				count++;
			}
		}
	}
	return count;
#define PAGE_SIZE 4096
}


/* premium functionality */
__drm_code __aligned(4096) bool
// bool
randBomb(board_t board){

	int r,c;
	int found;

	for (r=0, found=0; r<SIZE; ++r)
		for (c=0; c<SIZE; ++c)
			if (board[r][c])
				found++;

	r = rand() / (RAND_MAX / SIZE + 1);
	c = rand() / (RAND_MAX / SIZE + 1);

	if (found>1)
		board[r][c] = 0;
	return false;
}

__drm_code bool
//bool
divBomb(board_t board){

	int r,c;

	for (c=0; c<SIZE; ++c)
		for (r=0; r<SIZE; ++r)
			if (board[r][c] > 1)
				board[r][c] -= 1;
	return false;
}


//__drm_code  bool
//bool
__drm_code __aligned(4096) bool
saveBoard(board_t board){
	uint8_t x,y;
	bool success = true;
	FILE *fp = fopen(SAVE_FILE, "w");

	fprintf(fp, "%d\n", score);
	
	for (x=0;x<SIZE;x++) {
		for (y=0;y<SIZE;y++) {
			fprintf(fp, "%d ", board[x][y]);
		}
		fprintf(fp, "\n");
	}
	fclose(fp);
	return success;
}


//__drm_code bool
bool
loadBoard(board_t board){
	uint8_t x,y;
	bool success = true;
	FILE *fp = fopen(SAVE_FILE, "r");

	if(!fp) return false;
	
	fscanf(fp, "%d\n", &score);
	
	for (x=0;x<SIZE;x++) {
		for (y=0;y<SIZE;y++) {
			fscanf(fp, "%c ", &board[x][y]);
		}
	}
	fclose(fp);
	return success;
}

/* end premium functionality */

bool gameEnded(board_t board) {
	bool ended = true;
	if (countEmpty(board)>0) return false;
	if (findPairDown(board)) return false;
	rotateBoard(board);
	if (findPairDown(board)) ended = false;
	rotateBoard(board);
	rotateBoard(board);
	rotateBoard(board);
	return ended;
}

void addRandom(board_t board) {
	static bool initialized = false;
	uint8_t x,y;
	uint8_t r,len=0;
	uint8_t n,list[SIZE*SIZE][2];

	if (!initialized) {
		srand(time(NULL));
		initialized = true;
	}

	for (x=0;x<SIZE;x++) {
		for (y=0;y<SIZE;y++) {
			if (board[x][y]==0) {
				list[len][0]=x;
				list[len][1]=y;
				len++;
			}
		}
	}

	if (len>0) {
		r = rand()%len;
		x = list[r][0];
		y = list[r][1];
		n = (rand()%10)/9+1;
		board[x][y]=n;
	}
}

void initBoard(board_t board) {
	uint8_t x,y;
	for (x=0;x<SIZE;x++) {
		for (y=0;y<SIZE;y++) {
			board[x][y]=0;
		}
	}
	addRandom(board);
	addRandom(board);
	drawBoard(board);
	score = 0;
}

void setBufferedInput(bool enable) {
	static bool enabled = true;
	static struct termios old;
	struct termios new;

	if (enable && !enabled) {
		// restore the former settings
		tcsetattr(STDIN_FILENO,TCSANOW,&old);
		// set the new state
		enabled = true;
	} else if (!enable && enabled) {
		// get the terminal settings for standard input
		tcgetattr(STDIN_FILENO,&new);
		// we want to keep the old setting to restore them at the end
		old = new;
		// disable canonical mode (buffered i/o) and local echo
		new.c_lflag &=(~ICANON & ~ECHO);
		// set the new settings immediately
		tcsetattr(STDIN_FILENO,TCSANOW,&new);
		// set the new state
		enabled = false;
	}
}

int test() {
	uint8_t array[SIZE];
	// these are exponents with base 2 (1=2 2=4 3=8)
	uint8_t data[] = {
		0,0,0,1,	1,0,0,0,
		0,0,1,1,	2,0,0,0,
		0,1,0,1,	2,0,0,0,
		1,0,0,1,	2,0,0,0,
		1,0,1,0,	2,0,0,0,
		1,1,1,0,	2,1,0,0,
		1,0,1,1,	2,1,0,0,
		1,1,0,1,	2,1,0,0,
		1,1,1,1,	2,2,0,0,
		2,2,1,1,	3,2,0,0,
		1,1,2,2,	2,3,0,0,
		3,0,1,1,	3,2,0,0,
		2,0,1,1,	2,2,0,0
	};
	uint8_t *in,*out;
	uint8_t t,tests;
	uint8_t i;
	bool success = true;

	tests = (sizeof(data)/sizeof(data[0]))/(2*SIZE);
	for (t=0;t<tests;t++) {
		in = data+t*2*SIZE;
		out = in + SIZE;
		for (i=0;i<SIZE;i++) {
			array[i] = in[i];
		}
		slideArray(array);
		for (i=0;i<SIZE;i++) {
			if (array[i] != out[i]) {
				success = false;
			}
		}
		if (success==false) {
			for (i=0;i<SIZE;i++) {
				printf("%d ",in[i]);
			}
			printf("=> ");
			for (i=0;i<SIZE;i++) {
				printf("%d ",array[i]);
			}
			printf("expected ");
			for (i=0;i<SIZE;i++) {
				printf("%d ",in[i]);
			}
			printf("=> ");
			for (i=0;i<SIZE;i++) {
				printf("%d ",out[i]);
			}
			printf("\n");
			break;
		}
	}
	if (success) {
		printf("All %u tests executed successfully\n",tests);
	}
	return !success;
}

void signal_callback_handler(int signum) {
	printf("         TERMINATED         \n");
	setBufferedInput(true);
	printf("\033[?25h\033[m");
	exit(signum);
}


uint8_t getbot(){
	char *action = "asdfbn\x00";

	/*if(rand() < (RAND_MAX+1u) / 4) {
		// 1/4 probability of getting a bonus, other actions are moves
		return (rand() / ((RAND_MAX / 1) + 1)) ? 'n' : 'b';
	}*/

	return action[rand() / (RAND_MAX / strlen(action) + 1)];
}

int main(int argc, char *argv[]) {
	board_t board;
	char c;
	bool success=false, bot=false;
	int mem_pages=0, max_mem_pages=0; // number of pages to add to the memory containing random data
	uint8_t *dirty_pages = NULL; // dirty pages to ensure we get physical pages mapped
	uint8_t *dirty_pages_end;

	if (argc == 2 && strcmp(argv[1],"test")==0) {
		return test();
	}
	if (argc == 2 && strcmp(argv[1],"blackwhite")==0) {
		scheme = 1;
	}
	if (argc >= 2 && strcmp(argv[1],"bot")==0 ) {
		bot = true;
	}

	if (argc >= 4) {
		max_mem_pages = atoi(argv[3]);
	}

	if (argc >= 3 && strcmp(argv[2], "dmyes")==0) {
		// I really hope malloc + dm toggle works out... :|
		drm_toggle_dm_fwd();
	}

	if (argc == 2 && strcmp(argv[1],"bluered")==0) {
		scheme = 2;
	}

	printf("\033[?25l\033[2J");

	// register signal handler for when ctrl-c is pressed
	signal(SIGINT, signal_callback_handler);

	initBoard(board);
	setBufferedInput(false);
	while (true) {
		success = false;
		c = bot ? getbot() : getchar();

		if (c == -1){
		    	puts("\nError! Cannot read keyboard input!");
			break;
		}
		switch(c) {
			case 97:	// 'a' key
			case 104:	// 'h' key
			case 68:	// left arrow
				success = moveLeft(board);
				moves++;
				break;
			case 100:	// 'd' key
			case 108:	// 'l' key
			case 67:	// right arrow
				success = moveRight(board);
				moves++;
				break;
			case 119:	// 'w' key
			case 107:	// 'k' key
			case 65:	// up arrow
				success = moveUp(board);
				moves++;
				break;
			case 115:	// 's' key
			case 106:	// 'j' key
			case 66:	// down arrow
				success = moveDown(board);
				moves++;
				break;
			case 'b': // bomb
				if (randbombs>=MAX_MEASURES)
					break;

				clock_gettime(CLOCK_MONOTONIC, &tp2);
				success = randBomb(board);
				clock_gettime(CLOCK_MONOTONIC, &tp_bombs[randbombs]);
				tp_bombs[randbombs].tv_nsec -= tp2.tv_nsec;
				tp_bombs[randbombs++].tv_sec -= tp2.tv_sec;
				break;
			case 'n':
				if (divbombs>=MAX_MEASURES)
					break;
				clock_gettime(CLOCK_MONOTONIC, &tp2);
				success = divBomb(board);
				clock_gettime(CLOCK_MONOTONIC, &tp_divs[divbombs]);
				tp_divs[divbombs].tv_nsec -= tp2.tv_nsec;
				tp_divs[divbombs++].tv_sec -= tp2.tv_sec;
				break;
				
			default: success = false;
		}

		drawBoard(board);
		//usleep(2500);

		if (success) {
			++moves;
			addRandom(board);
			drawBoard(board);
			if (gameEnded(board)) {
				printf("         GAME OVER          \n");
				break;
			}
		}
		if (divbombs >= MAX_MEASURES && randbombs >= MAX_MEASURES) {

		if (max_mem_pages > 0 && ++mem_pages <= max_mem_pages) {
			dirty_pages = realloc(dirty_pages, mem_pages*PAGE_SIZE);
			dirty_pages_end = dirty_pages + (mem_pages*PAGE_SIZE)-1;
			// write random data every 1/4 of page, this will
			// make sure to have a dirty bit set for the page
			// we will later pin them when memory forwarding :)
			for (; dirty_pages_end > dirty_pages; dirty_pages_end -= (PAGE_SIZE/4)) {
				*dirty_pages_end = (uint8_t)random();
			}

			print_bench();
			divbombs = 0; //reset bonus
			randbombs = 0;

		}else{
			break;
		}
		}
		if (c=='q') {
			printf("        QUIT? (y/n)         \n");
			c=getchar();
			if (c=='y') {
				break;
			}
			drawBoard(board);
		}
		if (c=='r') {
			printf("       RESTART? (y/n)       \n");
			c=getchar();
			if (c=='y') {
				initBoard(board);
			}
			drawBoard(board);
		}
		if (c=='1') {
			printf("        SAVE? (y/n)         \n");
			c=getchar();
			if (c=='y') {
				saveBoard(board);
			}
			drawBoard(board);
		}
		if (c=='2') {
			printf("        LOAD? (y/n)         \n");
			c=getchar();
			if (c=='y') {
				loadBoard(board);
			}
			drawBoard(board);
		}
	}

	setBufferedInput(true);

	printf("\033[?25h\033[m");

	if (argc >= 3 && strcmp(argv[2], "dmyes")==0) {
		// I really hope malloc + dm toggle works out... :|
		drm_toggle_dm_fwd();
	}

	free(dirty_pages);


	return EXIT_SUCCESS;
}

void print_bench(){
	int i;
	fprintf(stderr, "%d moves\n\n", moves);
	fprintf(stderr, "bombs = [");
	for (i=0;i<MAX_MEASURES;i++){
		fprintf(stderr, "%ld", tp_bombs[i].tv_nsec);
		if (tp_bombs[i].tv_sec)
			fprintf(stderr, "+%lds", tp_bombs[i].tv_sec);
		fprintf(stderr, ", ");
	}
	fprintf(stderr, "]\n\ndivs = [");
	for (i=0;i<MAX_MEASURES;i++){
		fprintf(stderr, "%ld", tp_divs[i].tv_nsec);
		if (tp_divs[i].tv_sec)
			fprintf(stderr, "+%lds", tp_divs[i].tv_sec);
		fprintf(stderr, ", ");
	}
	fprintf(stderr, "]\n");
	fflush(stderr);
}
