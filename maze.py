width,height = 50,20
tiles = [[False for _ in range(height)] for _ in range(width)]
grid = [['#' for _ in range(2 * height + 1)] for _ in range(2 * width + 1)]

def get(x, y):
    if x < 0:
        return True
    if y < 0:
        return True
    if x >= len(tiles):
        return True
    if y >= len(tiles[x]):
        return True
    return tiles[x][y]

def get2(x, y):
    if x < 0:
        return ' '
    if y < 0:
        return ' '
    if x >= len(grid):
        return ' '
    if y >= len(grid[x]):
        return ' '
    return grid[x][y]

def setgrid(x, y):
    global grid
    if x == int(x) and y == int(y):
        tiles[x][y] = True
    grid[int(x * 2 + 1)][int(y * 2 + 1)] = ' '

setgrid(0, 0)

def printgrid():
    for y in range(height * 2 + 1):
        print(''.join(c[y] for c in grid))

import random

while True:
    #printgrid()

    paths = []
    for x in range(width):
        for y in range(height):
            if tiles[x][y]:
                for dx,dy in [(0, 1), (0, -1), (1, 0), (-1, 0)]:
                    if not get(x + dx, y + dy):
                        paths.append((x, y, dx, dy))

    #print(paths)
    
    if len(paths) == 0:
        break

    path = random.choice(paths)

    x,y,dx,dy = path

    setgrid(x + dx / 2, y + dy / 2)
    setgrid(x + dx, y + dy)

grid[1][0] = ' '
grid[-2][-1] = ' '

printgrid()

charset = ' ═══║╝╚╩║╗╔╦║╣╠╬'
charset = ' OO═O╝╚╩O╗╔╦║╣╠╬'
charset = ' oo-o+++o+++|+++'

for x in range(width * 2 + 1):
    for y in range(height * 2 + 1):
        if grid[x][y] != ' ':
            grid[x][y] = charset[int(''.join('01'[get2(x + dx, y + dy) != ' '] for dx,dy in [(0, 1), (0, -1), (1, 0), (-1, 0)]), 2)]

printgrid()