#include <ncurses.h>
#include <stdlib.h>

int main(void)
{
    initscr();
    start_color();

    init_pair(1,COLOR_BLACK,COLOR_RED);
    init_pair(2,COLOR_BLUE,COLOR_BLACK);
    attrset(COLOR_PAIR(1));
    addstr(0, 0, "My name is Mr. Black!\n");
    attrset(COLOR_PAIR(2));
    addstr(1, 0, "My name is Mr. Blue!\n");
    attrset(COLOR_PAIR(1));
    addstr("How do you do?\n");
    attrset(COLOR_PAIR(2));
    addstr("How do I do ");
    attron(A_BOLD);
    addstr("what");
    attroff(A_BOLD);
    addch('?');
    refresh();
    getch();

    endwin();
    return 0;
}