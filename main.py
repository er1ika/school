import pygame
back = (0,0,0)
screen = pygame.display.set_mode((500,500))
screen.fill(back)
end = True
while end:
    for event in pygame.event.get():
        if event.type == pygame.MOUSEBUTTONUP:
            pygame.quit()