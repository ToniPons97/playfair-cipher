#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>

#define SIZE 5
#define USED_SIZE_LIMIT 25
#define LOWER_BOUND 'a'
#define UPPER_BOUND 'z'
#define E_FLAG "-e"
#define D_FLAG "-d"

struct letter_position {
    int x;
    int y;
};

void create_playfair_sqr(char square[SIZE][SIZE], char* used_letters, char* key);
void draw_playfair_sqr(char square[SIZE][SIZE]);
bool is_used_letter(char* used, char letter);
void init_used_letters(char* used);
void init_playfair_sqr(char square[SIZE][SIZE], char init_char);
char find_next_letter(char* used);
void encrypt(char* plaintext, char square[SIZE][SIZE]);
void decrypt(char* ciphertext, char square[SIZE][SIZE]);
void format_input(char* input, char* formatted_input, char filler_character);

struct letter_position get_letter_position(char letter, char square[SIZE][SIZE]);

int main(int argc, char* argv[]) {
    if (argc != 4) {
        printf("[!] Incorrect command line arguments.\n");
        printf("Example: %s -e \"message\" \"key\"\n", argv[0]);
        printf("Example: %s -e \"message\" \"key\"\n", argv[0]);
        return 1;
    }

    if (strncmp(argv[1], E_FLAG, 2) && strncmp(argv[1], D_FLAG, 2)) {
        printf("[!] Invalid flag: it either be -e or -d.\n");
        return 1;
    }

    if (strlen(argv[2]) == 0 || strlen(argv[3]) == 0) {
        printf("[!] message and key shoudn't be empty.\n");
        return 1;
    }

    char *key = NULL, *input = NULL, *selected_flag = NULL;
    char used_letters[USED_SIZE_LIMIT];
    char playfair_square[SIZE][SIZE];

    selected_flag = (char*) calloc(2, sizeof(char));
    strncpy(selected_flag, argv[1], 2);

    key = (char*) calloc(strlen(argv[3]), sizeof(char));
    strncpy(key, argv[3], strlen(argv[3]));

    init_used_letters(used_letters);

    printf("Key: %s\n", argv[3]);
    printf("Message: %s\n", argv[2]);

    create_playfair_sqr(playfair_square, used_letters, key);

    free(key);
    key = NULL;

    draw_playfair_sqr(playfair_square);

    int input_size = strlen(argv[2]);
    input = (char*) calloc(input_size, sizeof(char));
    strncpy(input, argv[2], input_size);

    if (input == NULL) {
        printf("[!] Fatal error: unable to allocate memory.\n");
        return 1;
    }

    if (strncmp(selected_flag, E_FLAG, 2) == 0) {
        encrypt(input, playfair_square);
    } else if (strncmp(selected_flag, D_FLAG, 2) == 0) {
        decrypt(input, playfair_square);
    }

    free(selected_flag);
    selected_flag = NULL;

    free(input);
    input = NULL;

    return 0;
}

void draw_playfair_sqr(char square[SIZE][SIZE]) {
    printf("\n");
    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            printf("%c  ", square[i][j]);
        }
        printf("\n");
    }
}

void create_playfair_sqr(char square[SIZE][SIZE], char* used_letters, char* key) {
    int available_index = 0;
    int sqr_x = 0, sqr_y = 0;
    char current_char;
    bool is_used = false;
    
    for (int i = 0; i < strlen(key); i++) {
        current_char = key[i];
        is_used = is_used_letter(used_letters, current_char);

        if (!is_used && !isspace(current_char)) {
            used_letters[available_index++] = current_char;
        } else {
            continue;
        }

        if ((sqr_y < SIZE) && isalpha(current_char)) {
            square[sqr_x][sqr_y++] = current_char;
        } else {
            sqr_y = 0;
            sqr_x++;
            square[sqr_x][sqr_y++] = current_char;
        }
    }

    for (int i = sqr_x; i < SIZE; i++) {
        int j = (i == sqr_x) ? sqr_y : 0;
        for (; j < SIZE; j++) {
            char next_letter = find_next_letter(used_letters);
            square[i][j] = next_letter;
            used_letters[available_index++] = next_letter;
        }
        
        j++;
    }
}

bool is_used_letter(char* used, char letter) {
    for (int i = 0; i < strlen(used); i++) {
        if (used[i] == letter) {
            return true;
        }
    }

    return false;
}

void init_used_letters(char* used) {
    memset(used, '\0', USED_SIZE_LIMIT);
}

void init_playfair_sqr(char square[SIZE][SIZE], char init_char) {
    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            square[i][j] = init_char;
        }
    }
}

char find_next_letter(char* used) {
    char letter = 'a';

    while(is_used_letter(used, letter) || letter == 'j') {
        letter++;
    }

    return letter;
}

void encrypt(char* plaintext, char square[SIZE][SIZE]) {
    size_t plaintext_length = strlen(plaintext);
    char formatted_input[plaintext_length * 2];
    size_t output_length = strlen(formatted_input);
    char letter1, letter2;
    struct letter_position letter_pos_1, letter_pos_2;
    char output[output_length];

    memset(output, '\0', output_length);

    format_input(plaintext, formatted_input, 'x');

    char new_pair[2];
    int min_y, max_y;
    for (int index = 0; index < strlen(formatted_input); index += 2) {
        letter1 = formatted_input[index];
        letter2 = formatted_input[index + 1];
        letter_pos_1 = get_letter_position(letter1, square);
        letter_pos_2 = get_letter_position(letter2, square);

        if (letter_pos_1.x == letter_pos_2.x) {
            new_pair[0] = square[letter_pos_1.x][(letter_pos_1.y + 1) % SIZE];
            new_pair[1] = square[letter_pos_2.x][(letter_pos_2.y + 1) % SIZE];

            strncat(output, new_pair, 2);
        } else if (letter_pos_1.y == letter_pos_2.y) {
            new_pair[0] = square[(letter_pos_1.x + 1) % SIZE][letter_pos_1.y];
            new_pair[1] = square[(letter_pos_2.x + 1) % SIZE][letter_pos_2.y];

            strncat(output, new_pair, 2);
        } else {
            min_y = letter_pos_1.y <= letter_pos_2.y ? letter_pos_1.y : letter_pos_2.y;
            max_y = letter_pos_1.y == min_y ? letter_pos_2.y : letter_pos_1.y;

            letter_pos_1.y = letter_pos_1.y == min_y ? max_y : min_y;
            letter_pos_2.y = letter_pos_2.y == max_y ? min_y : max_y;

            new_pair[0] = square[letter_pos_1.x][letter_pos_1.y];
            new_pair[1] = square[letter_pos_2.x][letter_pos_2.y];

            strncat(output, new_pair, 2);
        }
    }

    printf("\nEncrypted: %s\n", output);
}

void decrypt(char* ciphertext, char square[SIZE][SIZE]) {
    size_t ciphertext_length = strlen(ciphertext);
    size_t output_length = ciphertext_length;
    char letter1, letter2;
    struct letter_position letter_pos_1, letter_pos_2;
    char output[output_length];

    memset(output, '\0', output_length);
    
    char new_pair[2], new_x_1, new_x_2, new_y_1, new_y_2;
    int min_y, max_y;
    for (int index = 0; index < strlen(ciphertext); index += 2) {
        letter1 = ciphertext[index];
        letter2 = ciphertext[index + 1];
        letter_pos_1 = get_letter_position(letter1, square);
        letter_pos_2 = get_letter_position(letter2, square);

        if (letter_pos_1.x == letter_pos_2.x) {
            new_y_1 = (letter_pos_1.y - 1) % SIZE;
            new_y_2 = (letter_pos_2.y - 1) % SIZE;

            new_pair[0] = square[letter_pos_1.x][new_y_1 < 0 ? new_y_1 + SIZE : new_y_1];
            new_pair[1] = square[letter_pos_2.x][new_y_2 < 0 ? new_y_2 + SIZE : new_y_2];

            strncat(output, new_pair, 2);
        } else if (letter_pos_1.y == letter_pos_2.y) {
            new_x_1 = (letter_pos_1.x - 1) % SIZE;
            new_x_2 = (letter_pos_2.x - 1) % SIZE;
            
            new_pair[0] = square[new_x_1 < 0 ? new_x_1 + SIZE : new_x_1][letter_pos_1.y];
            new_pair[1] = square[new_x_2 < 0 ? new_x_2 + SIZE : new_x_2][letter_pos_2.y];

            strncat(output, new_pair, 2);
        } else {
            min_y = letter_pos_1.y <= letter_pos_2.y ? letter_pos_1.y : letter_pos_2.y;
            max_y = letter_pos_1.y == min_y ? letter_pos_2.y : letter_pos_1.y;

            letter_pos_1.y = letter_pos_1.y == min_y ? max_y : min_y;
            letter_pos_2.y = letter_pos_2.y == max_y ? min_y : max_y;

            new_pair[0] = square[letter_pos_1.x][letter_pos_1.y];
            new_pair[1] = square[letter_pos_2.x][letter_pos_2.y];

            strncat(output, new_pair, 2);
        }
    }

    if (output[output_length - 1] == 'x') {
        output[output_length - 1] = '\0';
    }

    printf("\nDecrypted: %s\n", output);
}

void format_input(char* input, char* formatted_input, char filler_character) {
    size_t input_length = strlen(input);
    int result_index = 1;
    
    formatted_input[0] = input[0];

    for (int i = 1; i < input_length; i++) {
        if (input[i] == input[i - 1]) {
            formatted_input[result_index++] = filler_character;
        }
        formatted_input[result_index++] = input[i];
    }
    
    formatted_input[result_index] = '\0';

    if (strlen(formatted_input) % 2 != 0) {
        formatted_input[result_index] = filler_character;
        formatted_input[++result_index] = '\0';
    }
}

struct letter_position get_letter_position(char letter, char square[SIZE][SIZE]) {
    struct letter_position position = { -1, -1 };

    if (letter == 'j') {
        letter = 'i';
    }

    for (int i = 0; i < SIZE; i++) {
        for (int j = 0; j < SIZE; j++) {
            if (letter == square[i][j]) {
                position.x = i;
                position.y = j;

                return position;
            }
        }
    }

    return position;
}